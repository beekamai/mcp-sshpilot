/* Remote mode: MCP over Streamable HTTP. Every request carries a device token from the vault; each MCP session
 * owns its own SessionCtx, Server and vault key, and can only be used by the device that opened it. */

import { createServer as createHttpServer } from "http";
import type { IncomingMessage, ServerResponse } from "http";
import { createServer as createHttpsServer } from "https";
import { readFileSync, statSync } from "fs";
import { randomUUID } from "crypto";
import { BlockList, isIP, isIPv6 } from "net";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { ErrorCode, McpError, isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import type { ServerHooks } from "./mcp-server.js";
import { createCtx, destroyCtx } from "./state.js";
import { describeCallTarget } from "./handlers.js";
import type { SessionCtx } from "./state.js";
import {
  authenticate,
  authenticateGrant,
  ensureClientKey,
  GrantProfileStore,
  isGrantToken,
  listDevices,
  listGrants,
  pruneExpiredGrants,
  touchDevice,
  VaultProfileStore,
} from "./vault.js";
import { createOAuthEndpoints, DEFAULT_OAUTH_REDIRECTS, normalizePublicUrl } from "./oauth.js";
import type { OAuthEndpoints } from "./oauth.js";
import type { ProfileStore } from "./config.js";

export interface HttpLimits {
  maxBodyBytes: number;
  /** Body bytes buffered at once by all requests together (counted as received); past it a POST gets 503 with Retry-After. */
  maxBodyBytesTotal: number;
  maxSessionsPerDevice: number;
  maxSessionsTotal: number;
  /** Sessions all connector grants together may hold, so Anthropic's side can never take every slot from devices. */
  maxGrantSessions: number;
  /** A session with no request activity for this long is closed. An open GET event stream does not count as activity. */
  idleTimeoutMs: number;
  sweepIntervalMs: number;
  /** Tool calls of one session whose handler is still running (cancelled ones included); a POST that would exceed it gets 429. */
  maxCallsPerSession: number;
  /** Requests in flight per device or grant (open GET streams included); past it 429. */
  maxRequestsPerPrincipal: number;
  /** Requests in flight of all connector grants together, so devices always keep connections. */
  maxGrantRequests: number;
  authFailLimit: number;
  authFailWindowMs: number;
  /** Upper bound of the failed-auth table; the oldest entries are evicted beyond it. */
  rateLimitEntries: number;
  headersTimeoutMs: number;
  requestTimeoutMs: number;
}

export const DEFAULT_HTTP_LIMITS: HttpLimits = {
  maxBodyBytes: 8 * 1024 * 1024,
  maxBodyBytesTotal: 64 * 1024 * 1024,
  maxSessionsPerDevice: 4,
  maxSessionsTotal: 16,
  maxGrantSessions: 8,
  idleTimeoutMs: 30 * 60 * 1000,
  sweepIntervalMs: 30_000,
  maxCallsPerSession: 32,
  maxRequestsPerPrincipal: 64,
  maxGrantRequests: 128,
  authFailLimit: 10,
  authFailWindowMs: 5 * 60 * 1000,
  rateLimitEntries: 4096,
  headersTimeoutMs: 10_000,
  requestTimeoutMs: 60_000,
};

export interface HttpServerOptions {
  vaultPath: string;
  /** Builds the MCP Server for one session; its handlers must close over the given ctx (mode "remote") and run every
   * tool call through hooks.toolCall, which enforces the per-session call cap and writes the audit line. */
  buildServer: (ctx: SessionCtx, hooks: ServerHooks) => Server;
  /** Default 127.0.0.1. */
  host?: string;
  /** Default 8722; 0 picks a free port. */
  port?: number;
  tlsCert?: string;
  tlsKey?: string;
  /** Exact origins (scheme://host[:port]) a browser may call from. Default: none. */
  allowedOrigins?: string[];
  /** Allows plain HTTP on a non-loopback address. */
  insecureHttp?: boolean;
  /** Takes the client IP from the right-most X-Forwarded-For entry when the peer is a loopback/private address
   * (only behind a proxy you control). */
  trustProxy?: boolean;
  /** Lets profiles and proxies point at loopback/link-local addresses of this host. Default false. */
  allowLocalTargets?: boolean;
  /** Lets a session pin a profile's host key on its first connection (trust on first use). Default false: unpinned
   * profiles are refused until the owner pins them out of band. */
  allowTofu?: boolean;
  /** Closes everything on SIGINT/SIGTERM and exits. Default true. */
  handleSignals?: boolean;
  /** Operational and audit lines. Default: stderr. */
  log?: (line: string) => void;
  limits?: Partial<HttpLimits>;
  /** Claude connectors (OAuth 2.1, scoped grants). Off unless given. */
  oauth?: OAuthOptions;
}

export interface OAuthOptions {
  /** External origin (https://host[:port]): issuer, and <publicUrl>/mcp is the protected resource. */
  publicUrl: string;
  /** Redirect URIs accepted on top of DEFAULT_OAUTH_REDIRECTS (exact match). */
  redirectUris?: string[];
}

export interface HttpServerHandle {
  port: number;
  close(): Promise<void>;
}

type RequestId = string | number;

interface PostState {
  pending: Set<RequestId>;
  cancelled: boolean;
}

interface OpenRequest {
  post: PostState;
  delivered: boolean;
}

interface RunningCall {
  tool: string;
  /* Never logged: may hold passwords. Only describeCallTarget reads it. */
  args: unknown;
  start: number;
}

interface Principal {
  deviceId: string;
  deviceName: string;
  key: Buffer;
  grantId?: string;
}

interface Session {
  id: string;
  deviceId: string;
  deviceKey: string;
  deviceName: string;
  transport: WebStandardStreamableHTTPServerTransport;
  server: Server;
  ctx: SessionCtx;
  lastSeen: number;
  inflight: number;
  running: number;
  calls: Set<RunningCall>;
  open: Map<RequestId, OpenRequest>;
  /* Responses still being written for this session. */
  responses: Set<ServerResponse>;
  closed: boolean;
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly body: string,
    readonly headers: Record<string, string> = {}
  ) {
    super(`HTTP ${status}`);
  }
}

const rpcError = (code: number, message: string): string => JSON.stringify({ jsonrpc: "2.0", error: { code, message }, id: null });

/* Fixed bodies: a rejected request learns nothing beyond the status code. */
const BODY_UNAUTHORIZED = rpcError(-32001, "Unauthorized");
const BODY_SESSION_NOT_FOUND = rpcError(-32001, "Session not found");
const BODY_SESSION_REQUIRED = rpcError(-32000, "Bad Request: Mcp-Session-Id header is required");
const BODY_TOO_MANY_REQUESTS = rpcError(-32000, "Too many requests");
const BODY_TOO_MANY_SESSIONS = rpcError(-32000, "Too many sessions");
const BODY_TOO_MANY_CALLS = rpcError(-32000, "Too many concurrent tool calls in this session");
const BODY_DUPLICATE_ID = rpcError(-32600, "Invalid Request: request id already in use in this session");
const BODY_FORBIDDEN_ORIGIN = rpcError(-32000, "Forbidden origin");
const BODY_TOO_LARGE = rpcError(-32000, "Request body too large");
const BODY_UNSUPPORTED_MEDIA = rpcError(-32000, "Unsupported Media Type: Content-Type must be application/json");
const BODY_PARSE_ERROR = rpcError(-32700, "Parse error: Invalid JSON");
const BODY_INTERNAL = rpcError(-32603, "Internal error");
const BODY_SERVER_BUSY = rpcError(-32000, "Server busy, retry shortly");
const BODY_BATCH = rpcError(-32600, "Invalid Request: send one request per POST (JSON-RPC batches are not supported)");
/* A client that stops reading keeps its response, and every result queued behind it, in memory until it goes away. */
const DRAIN_TIMEOUT_MS = 60_000;
const WRITE_SLICE_BYTES = 64 * 1024;

/* Rejected before auth: an anonymous client gets this much body drained for a clean response, then the socket. */
const PRE_AUTH_DRAIN_BYTES = 64 * 1024;
const PRE_AUTH_STATUSES = new Set([401, 403, 405, 429, 500]);

const CORS_ALLOW_HEADERS = "Authorization, Content-Type, Accept, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID";
const CORS_EXPOSE_HEADERS = "Mcp-Session-Id, WWW-Authenticate";

/* Never handed to the SDK: request info reaches tool handlers, and the token must not travel past this file. */
const STRIPPED_HEADERS = new Set(["authorization", "proxy-authorization", "cookie"]);

/* Peers whose X-Forwarded-For --trust-proxy honours: a proxy on this host or a private network, never the internet. */
const PROXY_PEERS = new BlockList();
PROXY_PEERS.addSubnet("127.0.0.0", 8, "ipv4");
PROXY_PEERS.addSubnet("10.0.0.0", 8, "ipv4");
PROXY_PEERS.addSubnet("172.16.0.0", 12, "ipv4");
PROXY_PEERS.addSubnet("192.168.0.0", 16, "ipv4");
PROXY_PEERS.addAddress("::1", "ipv6");
PROXY_PEERS.addSubnet("fc00::", 7, "ipv6");

function isProxyPeer(ip: string): boolean {
  const v = ip.startsWith("::ffff:") && ip.includes(".") ? ip.slice(7) : ip;
  const family = isIP(v);
  return family !== 0 && PROXY_PEERS.check(v, family === 6 ? "ipv6" : "ipv4");
}

function isLoopbackHost(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  return h === "localhost" || h === "::1" || /^127\.\d+\.\d+\.\d+$/.test(h) || /^::ffff:127\.\d+\.\d+\.\d+$/.test(h);
}

/* Log-line safe: no spaces, quotes or control chars that could forge an extra audit entry. */
function clean(s: unknown, max = 64): string {
  const t = String(s ?? "").replace(/[^\w.@:\-]/g, "?").slice(0, max);
  return t.length > 0 ? t : "-";
}

function expandIPv6(ip: string): string[] | null {
  const [head, tail] = ip.split("::");
  if (ip.split("::").length > 2) return null;
  const h = head ? head.split(":") : [];
  const t = tail !== undefined ? (tail ? tail.split(":") : []) : [];
  const fill = tail !== undefined ? 8 - h.length - t.length : 0;
  if (fill < 0) return null;
  return [...h, ...Array(fill).fill("0"), ...t];
}

/* IPv6 clients usually own a whole /64; keying by full address would let one host reset its limit for free. */
function rateKey(ip: string): string {
  const v = ip.startsWith("::ffff:") && ip.includes(".") ? ip.slice(7) : ip;
  if (!isIPv6(v)) return v;
  const groups = expandIPv6(v.split("%")[0]);
  return groups ? groups.slice(0, 4).map((g) => g.toLowerCase().replace(/^0+(?=.)/, "")).join(":") + "::/64" : v;
}

/** Failed-auth counter per client: fixed window, never reset by a success, bounded size. */
class FailLimiter {
  private readonly entries = new Map<string, { count: number; start: number }>();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    private readonly maxEntries: number
  ) {}

  /** Seconds until the client may try again, or 0 when it is not blocked. */
  retryAfter(key: string, now: number): number {
    const e = this.entries.get(key);
    if (!e) return 0;
    if (now - e.start >= this.windowMs) {
      this.entries.delete(key);
      return 0;
    }
    return e.count >= this.limit ? Math.max(1, Math.ceil((e.start + this.windowMs - now) / 1000)) : 0;
  }

  /** Returns true when this failure is the one that blocks the client. */
  fail(key: string, now: number): boolean {
    let e = this.entries.get(key);
    if (e && now - e.start >= this.windowMs) {
      this.entries.delete(key);
      e = undefined;
    }
    if (!e) {
      this.evict(now);
      e = { count: 0, start: now };
      this.entries.set(key, e);
    }
    e.count++;
    return e.count === this.limit;
  }

  private evict(now: number): void {
    if (this.entries.size < this.maxEntries) return;
    for (const [k, e] of this.entries) {
      if (now - e.start >= this.windowMs) this.entries.delete(k);
    }
    /* Still full: drop the oldest windows (Map keeps insertion order). */
    for (const k of this.entries.keys()) {
      if (this.entries.size < this.maxEntries) break;
      this.entries.delete(k);
    }
  }

  clear(): void {
    this.entries.clear();
  }
}

/** Body bytes buffered right now by every request together. Charged as they arrive, so a client that declares a large
 * body and sends nothing holds none of it. */
interface BodyBudget {
  inFlight: number;
  max: number;
}

function readBody(req: IncomingMessage, max: number, budget: BodyBudget): Promise<Buffer> {
  const declared = Number(req.headers["content-length"]);
  if (Number.isFinite(declared) && declared > max) {
    return Promise.reject(new HttpError(413, BODY_TOO_LARGE));
  }
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    const done = (err?: HttpError): void => {
      req.off("data", onData);
      req.off("end", onEnd);
      req.off("error", onError);
      req.off("aborted", onAborted);
      /* The buffer leaves this function either way: the caller parses it at once and drops it. */
      budget.inFlight -= total;
      if (err) reject(err);
      else resolve(Buffer.concat(chunks, total));
    };
    const onData = (c: Buffer): void => {
      if (total + c.length > max) {
        chunks.length = 0;
        req.pause();
        done(new HttpError(413, BODY_TOO_LARGE));
        return;
      }
      if (budget.inFlight + c.length > budget.max) {
        chunks.length = 0;
        req.pause();
        done(new HttpError(503, BODY_SERVER_BUSY, { "Retry-After": "1" }));
        return;
      }
      total += c.length;
      budget.inFlight += c.length;
      chunks.push(c);
    };
    const onEnd = (): void => done();
    const onError = (): void => done(new HttpError(400, BODY_PARSE_ERROR));
    const onAborted = (): void => done(new HttpError(400, BODY_PARSE_ERROR));
    req.on("data", onData);
    req.on("end", onEnd);
    req.on("error", onError);
    req.on("aborted", onAborted);
  });
}

/* Reads and drops the unread rest of a rejected request so the client sees the response instead of a reset;
 * past `limit` bytes the socket is destroyed. Taking 'data' here also stops Node's unbounded auto-dump. */
function discardBody(req: IncomingMessage, limit: number): void {
  if (req.complete || req.destroyed) return;
  let seen = 0;
  req.on("data", (c: Buffer) => {
    seen += c.length;
    if (seen > limit) req.destroy();
  });
  req.resume();
}

/* JSON-RPC batches are gone from the MCP spec since 2025-06-18. With one, a cancelled request leaves the results of
 * its siblings queued in the SDK until the session ends, so remote mode takes at most one request per POST. */
function refuseBatch(body: unknown): void {
  if (Array.isArray(body) && (requestIds(body)?.length ?? 2) > 1) throw new HttpError(400, BODY_BATCH);
}

function countToolCalls(body: unknown): number {
  const isCall = (m: unknown): boolean => typeof m === "object" && m !== null && (m as { method?: unknown }).method === "tools/call" && "id" in m;
  return Array.isArray(body) ? body.filter(isCall).length : isCall(body) ? 1 : 0;
}

/** Ids of the requests in a POST body, or null when one id appears twice in it. */
function requestIds(body: unknown): RequestId[] | null {
  const ids = new Set<RequestId>();
  for (const m of Array.isArray(body) ? body : [body]) {
    if (typeof m !== "object" || m === null || typeof (m as { method?: unknown }).method !== "string") continue;
    const id = (m as { id?: unknown }).id;
    if (typeof id !== "string" && typeof id !== "number") continue;
    if (ids.has(id)) return null;
    ids.add(id);
  }
  return [...ids];
}

function headerValue(req: IncomingMessage, name: string): string | undefined {
  const v = req.headers[name];
  return Array.isArray(v) ? v.join(", ") : v;
}

function toWebRequest(req: IncomingMessage, pathname: string): Request {
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined || STRIPPED_HEADERS.has(k)) continue;
    headers.set(k, Array.isArray(v) ? v.join(", ") : v);
  }
  /* Fixed host: the SDK only needs a parseable URL, and the Host header is client-controlled. */
  return new Request(`http://localhost${pathname}`, { method: req.method, headers });
}

/** Streams a web Response (JSON or SSE) into the Node response; cancels the source when the client goes away. */
async function writeWebResponse(res: ServerResponse, response: Response): Promise<void> {
  const headers: Record<string, string> = {};
  response.headers.forEach((v, k) => { headers[k] = v; });
  res.writeHead(response.status, headers);
  if (!response.body) {
    res.end();
    return;
  }
  res.flushHeaders();
  const reader = response.body.getReader();
  const onClose = (): void => { reader.cancel().catch(() => {}); };
  res.once("close", onClose);
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done || res.destroyed) break;
      /* One tool result is one chunk (megabytes); written in slices, the drain deadline means "no progress", not
       * "a slow reader could not take the whole result in time". */
      for (let off = 0; off < value.length && !res.destroyed; off += WRITE_SLICE_BYTES) {
        if (res.write(value.subarray(off, off + WRITE_SLICE_BYTES))) continue;
        await new Promise<void>((resolve) => {
          const stalled = setTimeout(() => res.destroy(), DRAIN_TIMEOUT_MS);
          const go = (): void => { clearTimeout(stalled); res.off("drain", go); res.off("close", go); resolve(); };
          res.on("drain", go);
          res.on("close", go);
        });
      }
    }
  } catch {
    /* Source errored or was cancelled: end what we have. */
  } finally {
    res.off("close", onClose);
    if (!res.destroyed && !res.writableEnded) res.end();
  }
}

function sendFixed(res: ServerResponse, status: number, body: string, headers: Record<string, string> = {}): void {
  if (res.headersSent) {
    res.destroy();
    return;
  }
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": String(Buffer.byteLength(body)), ...headers });
  res.end(body);
}

/** Starts the remote MCP endpoint (/mcp) and a bare liveness probe (/healthz). */
export function startHttpServer(opts: HttpServerOptions): Promise<HttpServerHandle> {
  const limits: HttpLimits = { ...DEFAULT_HTTP_LIMITS, ...opts.limits };
  const bodyBudget: BodyBudget = { inFlight: 0, max: limits.maxBodyBytesTotal };
  const host = opts.host ?? "127.0.0.1";
  const port = opts.port ?? 8722;
  const log = opts.log ?? ((line: string) => console.error(line));
  const vaultPath = opts.vaultPath;
  const useTls = Boolean(opts.tlsCert || opts.tlsKey);

  if (useTls && !(opts.tlsCert && opts.tlsKey)) {
    return Promise.reject(new Error("TLS needs both --tls-cert and --tls-key"));
  }
  if (!useTls && !isLoopbackHost(host) && !opts.insecureHttp) {
    return Promise.reject(
      new Error(
        `Refusing plain HTTP on non-loopback address ${host}: device tokens would cross the network unencrypted. ` +
          `Use --tls-cert/--tls-key, bind 127.0.0.1 behind a TLS reverse proxy, or pass --insecure-http if a proxy on a private network terminates TLS.`
      )
    );
  }
  const allowedOrigins = new Set<string>();
  for (const o of opts.allowedOrigins ?? []) {
    const n = o.trim().toLowerCase().replace(/\/+$/, "");
    if (n === "*" || n.length === 0)
      return Promise.reject(new Error(`Invalid allowed origin "${o}": list exact origins, wildcards are not supported`));
    allowedOrigins.add(n);
  }
  try {
    statSync(vaultPath);
  } catch {
    return Promise.reject(new Error(`Vault not found at ${vaultPath}; create it with \`mcp-sshpilot vault init\``));
  }
  let tlsOptions: { cert: Buffer; key: Buffer } | null = null;
  if (useTls) {
    try {
      tlsOptions = { cert: readFileSync(opts.tlsCert!), key: readFileSync(opts.tlsKey!) };
    } catch (e) {
      const code = (e as NodeJS.ErrnoException)?.code ?? "read error";
      return Promise.reject(new Error(`Cannot read TLS certificate or key (${code})`));
    }
  }
  let publicUrl: string | null = null;
  if (opts.oauth) {
    try {
      publicUrl = normalizePublicUrl(opts.oauth.publicUrl);
      /* Registration never writes the vault: one from before `vault init` made the client-id key gets it here, once. */
      if (ensureClientKey(vaultPath)) log(`${new Date().toISOString()} oauth: client id key added to the vault`);
    } catch (e) {
      return Promise.reject(e);
    }
  }

  /* RFC 9728: with OAuth on, a 401 tells the client where to start the authorization flow. */
  const unauthorized = (): HttpError =>
    new HttpError(401, BODY_UNAUTHORIZED, {
      "WWW-Authenticate": publicUrl ? `Bearer resource_metadata="${publicUrl}/.well-known/oauth-protected-resource"` : 'Bearer realm="mcp-sshpilot"',
    });

  const sessions = new Map<string, Session>();
  const limiter = new FailLimiter(limits.authFailLimit, limits.authFailWindowMs, limits.rateLimitEntries);
  let oauth: OAuthEndpoints | null = null;
  let closing: Promise<void> | null = null;

  const audit = (s: Session, tool: string, args: unknown, ms: number, outcome: string): void => {
    const target = clean(describeCallTarget(s.ctx, args, tool), 300);
    log(`${new Date().toISOString()} audit device=${clean(s.deviceName)} session=${s.id.slice(0, 8)} tool=${clean(tool)} target=${target} ms=${ms} ${outcome}`);
  };

  const closeSession = (s: Session, reason: string): void => {
    if (s.closed) return;
    s.closed = true;
    if (sessions.get(s.id) === s) sessions.delete(s.id);
    const now = Date.now();
    for (const call of s.calls) audit(s, call.tool, call.args, now - call.start, "aborted");
    s.calls.clear();
    s.open.clear();
    /* An open response would otherwise keep its queued results until the client goes away. */
    for (const r of s.responses) r.destroy();
    s.responses.clear();
    /* Drops every SSH connection, background jobs and the temp dir, and zero-fills the vault key. */
    destroyCtx(s.ctx);
    s.server.close().catch(() => {});
    log(`${new Date().toISOString()} session closed device=${clean(s.deviceName)} session=${s.id.slice(0, 8)} reason=${reason}`);
  };

  /* Fail closed: an unreadable vault ends every session, since none can prove its device still exists. A grant
   * counts while it exists and has not expired. */
  const liveDeviceKeys = (): Set<string> => {
    try {
      const live = new Set(listDevices(vaultPath).map((d) => `${d.id}:${d.createdAt}`));
      for (const g of listGrants(vaultPath)) if (!g.expired) live.add(`grant:${g.id}:${g.createdAt}`);
      return live;
    } catch {
      return new Set<string>();
    }
  };

  /* The session-owning key of a live principal, or null when its device or grant is gone (or expired). */
  const liveKeyOf = (p: Principal): string | null => {
    if (p.grantId) {
      const g = listGrants(vaultPath).find((x) => x.id === p.grantId && !x.expired);
      return g ? `grant:${g.id}:${g.createdAt}` : null;
    }
    const d = listDevices(vaultPath).find((x) => x.id === p.deviceId);
    return d ? `${d.id}:${d.createdAt}` : null;
  };

  /* Grant tokens are only accepted while OAuth is on; anything else goes through the device check, so a missing or
   * malformed header costs the same work as a wrong device token. */
  const authenticatePrincipal = (token: string): Principal | null => {
    if (publicUrl && isGrantToken(token)) {
      const g = authenticateGrant(vaultPath, token);
      return g ? { deviceId: `grant:${g.grantId}`, deviceName: `grant:${g.label}`, key: g.gdek, grantId: g.grantId } : null;
    }
    const a = authenticate(vaultPath, token);
    return a ? { deviceId: a.deviceId, deviceName: a.deviceName, key: a.dek } : null;
  };

  const enforceRevocations = (): void => {
    if (sessions.size === 0) return;
    const live = liveDeviceKeys();
    for (const s of [...sessions.values()]) {
      if (!live.has(s.deviceKey)) closeSession(s, s.deviceId.startsWith("grant:") ? "grant-ended" : "device-revoked");
    }
  };

  const sweep = (): void => {
    oauth?.sweep();
    /* Grants stay in the file while --oauth is off, so their expired wraps (and sealed retry responses past their
     * window) must leave it either way. */
    try {
      pruneExpiredGrants(vaultPath);
    } catch {
      /* Unreadable vault: enforceRevocations below ends every session. */
    }
    enforceRevocations();
    const now = Date.now();
    for (const s of [...sessions.values()]) {
      /* Open POST streams alone do not keep a session: one whose request will never be answered must not pin the
       * vault key in memory. Closing the transport ends such streams. */
      if (s.running === 0 && now - s.lastSeen > limits.idleTimeoutMs) closeSession(s, "idle");
    }
  };
  const sweepTimer = setInterval(sweep, limits.sweepIntervalMs);
  sweepTimer.unref();

  const clientIp = (req: IncomingMessage): string => {
    const peer = req.socket.remoteAddress ?? "unknown";
    if (opts.trustProxy && isProxyPeer(peer)) {
      const xff = headerValue(req, "x-forwarded-for");
      const last = xff?.split(",").map((p) => p.trim()).filter(Boolean).pop();
      /* Only an address: any other string would become a limiter key of its own (memory, evicting real entries). */
      if (last && isIP(last)) return last;
    }
    return peer;
  };

  /* Picks room for one more session of this device: evicts its least recently used idle session at the cap. */
  const makeRoom = (deviceId: string): boolean => {
    const own = [...sessions.values()].filter((s) => s.deviceId === deviceId);
    if (own.length >= limits.maxSessionsPerDevice) {
      const idle = own.filter((s) => s.inflight === 0 && s.running === 0).sort((a, b) => a.lastSeen - b.lastSeen)[0];
      if (!idle) return false;
      closeSession(idle, "evicted");
      return true;
    }
    if (deviceId.startsWith("grant:") && [...sessions.values()].filter((s) => s.deviceId.startsWith("grant:")).length >= limits.maxGrantSessions) return false;
    return sessions.size < limits.maxSessionsTotal;
  };

  /* Counts and audits around the real handler, not transport messages: a reused id or a cancellation cannot hide
   * a running call from the cap or from the audit log. */
  const trackCall = async <T>(s: Session, tool: string, args: unknown, signal: AbortSignal, run: () => Promise<T>): Promise<T> => {
    /* The hard cap; the 429 in handleMcp is the cheap early answer, this one also holds for racing POSTs. */
    if (s.running >= limits.maxCallsPerSession) {
      audit(s, tool, args, 0, "refused");
      throw new McpError(ErrorCode.InvalidRequest, "Too many concurrent tool calls in this session");
    }
    const call: RunningCall = { tool, args, start: Date.now() };
    s.running++;
    s.calls.add(call);
    let outcome = "error";
    try {
      const result = await run();
      if ((result as { isError?: boolean } | undefined)?.isError !== true) outcome = "ok";
      return result;
    } finally {
      s.running--;
      /* Gone from the set: closeSession already audited it as aborted. */
      if (s.calls.delete(call)) audit(s, tool, args, Date.now() - call.start, signal.aborted ? "cancelled" : outcome);
    }
  };

  const forget = (s: Session, id: RequestId): PostState | undefined => {
    const open = s.open.get(id);
    if (!open) return undefined;
    s.open.delete(id);
    open.post.pending.delete(id);
    return open.post;
  };

  const instrument = (s: Session): void => {
    /* Set before server.connect(): Protocol chains a pre-existing onmessage/onclose instead of replacing it. */
    s.transport.onmessage = (message) => {
      if (!("method" in message)) return;
      if ("id" in message) {
        const open = s.open.get(message.id);
        if (open) open.delivered = true;
        return;
      }
      if (message.method !== "notifications/cancelled") return;
      const rid = message.params?.requestId;
      /* Same test as the SDK, which ignores a falsy id (that call is then answered normally). */
      if (!rid || (typeof rid !== "string" && typeof rid !== "number") || !s.open.get(rid)?.delivered) return;
      const post = forget(s, rid)!;
      post.cancelled = true;
      /* The SDK never answers a cancelled request, so its POST stream would stay open for good; end it once
       * nothing else on it is waiting. The handler itself keeps its slot until it really ends (trackCall). */
      if (post.pending.size === 0) s.transport.closeSSEStream(rid);
    };
    s.transport.onclose = () => closeSession(s, "closed");
    const send = s.transport.send.bind(s.transport);
    s.transport.send = async (message, options) => {
      const id = "id" in message && message.id !== undefined && ("result" in message || "error" in message) ? message.id : undefined;
      const post = id === undefined ? undefined : forget(s, id);
      await send(message, options);
      /* The SDK waits for every id of a stream, cancelled ones included; this answer was the last one coming. */
      if (post?.cancelled && post.pending.size === 0) s.transport.closeSSEStream(id!);
    };
  };

  const openSession = async (auth: Principal, deviceKey: string): Promise<Session> => {
    const id = randomUUID();
    let store: ProfileStore;
    try {
      store = auth.grantId ? new GrantProfileStore(vaultPath, auth.grantId, auth.key) : new VaultProfileStore(vaultPath, auth.key);
    } catch (e) {
      auth.key.fill(0);
      throw e;
    }
    const ctx = createCtx({
      store,
      mode: "remote",
      deviceId: auth.deviceId,
      scoped: auth.grantId !== undefined,
      allowLocalTargets: opts.allowLocalTargets === true,
      allowTofu: opts.allowTofu === true,
    });
    let server: Server;
    let self: Session | undefined;
    const hooks: ServerHooks = {
      toolCall: (tool, args, signal, run) => (self ? trackCall(self, tool, args, signal, run) : run()),
    };
    try {
      server = opts.buildServer(ctx, hooks);
    } catch (e) {
      destroyCtx(ctx);
      throw e;
    }
    const s: Session = {
      id,
      deviceId: auth.deviceId,
      deviceKey,
      deviceName: auth.deviceName,
      transport: new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: () => id }),
      server,
      ctx,
      lastSeen: Date.now(),
      inflight: 0,
      running: 0,
      calls: new Set(),
      open: new Map(),
      responses: new Set(),
      closed: false,
    };
    self = s;
    /* Registered before any await so concurrent initializations count against the limits. */
    sessions.set(id, s);
    instrument(s);
    try {
      await server.connect(s.transport);
    } catch (e) {
      closeSession(s, "connect-failed");
      throw e;
    }
    return s;
  };

  /* In-flight requests per principal (device or grant), so that one of them, or the connector grants together,
   * cannot hold every server connection and starve the owner's devices. Released when the response closes. */
  const requestSlots = new Map<string, number>();
  let grantRequests = 0;
  const takeRequestSlot = (p: Principal, res: ServerResponse): void => {
    const held = requestSlots.get(p.deviceId) ?? 0;
    if (held >= limits.maxRequestsPerPrincipal || (p.grantId && grantRequests >= limits.maxGrantRequests)) {
      throw new HttpError(429, BODY_TOO_MANY_REQUESTS, { "Retry-After": "1" });
    }
    requestSlots.set(p.deviceId, held + 1);
    if (p.grantId) grantRequests++;
    res.once("close", () => {
      const left = (requestSlots.get(p.deviceId) ?? 1) - 1;
      if (left > 0) requestSlots.set(p.deviceId, left);
      else requestSlots.delete(p.deviceId);
      if (p.grantId) grantRequests--;
    });
  };

  const forward = async (s: Session, req: IncomingMessage, res: ServerResponse, pathname: string, parsedBody?: unknown): Promise<void> => {
    const counted = req.method !== "GET";
    if (counted) s.inflight++;
    s.responses.add(res);
    res.once("close", () => s.responses.delete(res));
    s.lastSeen = Date.now();
    /* Callers checked these ids against s.open with no await in between. */
    const ids = parsedBody === undefined ? [] : requestIds(parsedBody) ?? [];
    const post: PostState = { pending: new Set(ids), cancelled: false };
    for (const id of ids) s.open.set(id, { post, delivered: false });
    try {
      const response = await s.transport.handleRequest(toWebRequest(req, pathname), parsedBody === undefined ? undefined : { parsedBody });
      await writeWebResponse(res, response);
    } finally {
      if (counted) s.inflight--;
      s.lastSeen = Date.now();
      /* Rejected by the transport before it reached the SDK: these ids are free again. */
      for (const id of ids) if (s.open.get(id)?.delivered === false) forget(s, id);
    }
  };

  const handleMcp = async (req: IncomingMessage, res: ServerResponse, pathname: string): Promise<void> => {
    const method = req.method ?? "";
    const origin = headerValue(req, "origin");
    if (origin !== undefined) {
      const n = origin.trim().toLowerCase();
      if (!allowedOrigins.has(n)) throw new HttpError(403, BODY_FORBIDDEN_ORIGIN);
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Access-Control-Expose-Headers", CORS_EXPOSE_HEADERS);
      res.setHeader("Vary", "Origin");
    }
    if (method === "OPTIONS") {
      if (origin === undefined) throw new HttpError(405, "", { Allow: "GET, POST, DELETE" });
      res.writeHead(204, {
        "Access-Control-Allow-Methods": "GET, POST, DELETE",
        "Access-Control-Allow-Headers": CORS_ALLOW_HEADERS,
        "Access-Control-Max-Age": "600",
      });
      res.end();
      return;
    }
    if (method !== "POST" && method !== "GET" && method !== "DELETE") {
      throw new HttpError(405, "", { Allow: "GET, POST, DELETE" });
    }

    /* Before auth: a revoked device's next request fails with 401, and its live sessions (SSH connections, vault
     * key) must end right then, not at the next sweep. Cheap: the device list is cached by the vault file's stat. */
    enforceRevocations();

    const authz = headerValue(req, "authorization") ?? "";
    const m = /^Bearer[ \t]+(\S+)[ \t]*$/i.exec(authz);
    /* Always runs authenticate, even for a missing or malformed header, so every rejection costs the same work. */
    let auth: Principal | null;
    try {
      auth = authenticatePrincipal(m ? m[1] : "");
    } catch (e) {
      log(`${new Date().toISOString()} vault unreadable (${clean((e as NodeJS.ErrnoException)?.code ?? "invalid", 32)}); rejecting requests`);
      throw new HttpError(500, BODY_INTERNAL);
    }
    /* Auth runs on headers only, before a single body byte is read. The limiter only ever answers failures: a
     * valid token always passes, so whoever shares an address with the owner (a reverse proxy without
     * --trust-proxy, NAT) cannot lock the owner out. Guessing a 256-bit secret is not what it protects against.
     * No bearer token is no guess, and with OAuth on a grant-shaped token is not counted either: a stale one is the
     * connector's cue to refresh (connectors share Anthropic's egress addresses with every other Claude user), and
     * answering an unknown grant id differently from a known one would tell which grants exist. */
    if (!auth) {
      if (!m || (publicUrl && isGrantToken(m[1]))) throw unauthorized();
      const ipKey = rateKey(clientIp(req));
      const now = Date.now();
      const wait = limiter.retryAfter(ipKey, now);
      if (wait > 0) throw new HttpError(429, BODY_TOO_MANY_REQUESTS, { "Retry-After": String(wait), ...unauthorized().headers });
      if (limiter.fail(ipKey, now)) log(`${new Date().toISOString()} auth blocked ip=${clean(ipKey)} for ${Math.round(limits.authFailWindowMs / 1000)}s`);
      throw unauthorized();
    }

    /* From here the key is ours: it either moves into a new session's store or is zeroed in finally. */
    let dek: Buffer | null = auth.key;
    try {
      takeRequestSlot(auth, res);
      const sessionId = headerValue(req, "mcp-session-id");
      if (sessionId !== undefined) {
        dek.fill(0);
        dek = null;
        const s = sessions.get(sessionId);
        /* Another device's session answers exactly like a nonexistent one. */
        if (!s || s.closed || s.deviceId !== auth.deviceId) throw new HttpError(404, BODY_SESSION_NOT_FOUND);
        let body: unknown;
        if (method === "POST") {
          body = await parseJsonBody(req);
          /* Reading the body can take up to the request timeout; a device revoked meanwhile must not get it run. */
          enforceRevocations();
          refuseBatch(body);
          const ids = requestIds(body);
          if (!ids || ids.some((id) => s.open.has(id))) throw new HttpError(400, BODY_DUPLICATE_ID);
          if (!s.closed && s.running + countToolCalls(body) > limits.maxCallsPerSession) {
            throw new HttpError(429, BODY_TOO_MANY_CALLS, { "Retry-After": "1" });
          }
        }
        if (s.closed) throw new HttpError(404, BODY_SESSION_NOT_FOUND);
        await forward(s, req, res, pathname, body);
        return;
      }

      if (method !== "POST") throw new HttpError(400, BODY_SESSION_REQUIRED);
      const body = await parseJsonBody(req);
      const isInit = Array.isArray(body) ? body.some((b) => isInitializeRequest(b)) : isInitializeRequest(body);
      if (!isInit) throw new HttpError(400, BODY_SESSION_REQUIRED);
      refuseBatch(body);
      if (!requestIds(body)) throw new HttpError(400, BODY_DUPLICATE_ID);
      if (countToolCalls(body) > limits.maxCallsPerSession) throw new HttpError(429, BODY_TOO_MANY_CALLS, { "Retry-After": "1" });
      const liveKey = liveKeyOf(auth);
      if (!liveKey) throw unauthorized();
      if (!makeRoom(auth.deviceId)) throw new HttpError(429, BODY_TOO_MANY_SESSIONS, { "Retry-After": "60" });

      const handed: Principal = { ...auth, key: dek };
      dek = null;
      const s = await openSession(handed, liveKey);
      try {
        await forward(s, req, res, pathname, body);
      } finally {
        /* The SDK rejected the initialize (e.g. 406 on a bad Accept header): no session was established. */
        if (s.transport.sessionId !== s.id) closeSession(s, "init-rejected");
      }
      if (!s.closed) {
        log(`${new Date().toISOString()} session opened device=${clean(s.deviceName)} session=${s.id.slice(0, 8)}`);
        if (!auth.grantId) {
          try {
            touchDevice(vaultPath, s.deviceId);
          } catch { /* lastUsedAt is best effort */ }
        }
      }
    } finally {
      dek?.fill(0);
    }
  };

  const parseJsonBody = async (req: IncomingMessage): Promise<unknown> => {
    const ct = headerValue(req, "content-type") ?? "";
    if (!/^application\/json\s*(;|$)/i.test(ct.trim())) throw new HttpError(415, BODY_UNSUPPORTED_MEDIA);
    const enc = headerValue(req, "content-encoding");
    if (enc && enc.toLowerCase() !== "identity") throw new HttpError(415, BODY_UNSUPPORTED_MEDIA);
    /* Bodies are buffered whole: without a shared budget, parallel slow POSTs of up to maxBodyBytes each add up past
     * the process memory limit. */
    const raw = await readBody(req, limits.maxBodyBytes, bodyBudget);
    try {
      return JSON.parse(raw.toString("utf-8"));
    } catch {
      throw new HttpError(400, BODY_PARSE_ERROR);
    }
  };

  const onRequest = (req: IncomingMessage, res: ServerResponse): void => {
    /* An unhandled 'error' on either stream would take the whole process (and every session) down. */
    req.on("error", () => {});
    res.on("error", () => {});
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");

    /* Every answer outside /mcp is unauthenticated: never let Node drain an unread body there without a limit. */
    let pathname: string;
    try {
      pathname = new URL(req.url ?? "/", "http://localhost").pathname;
    } catch {
      discardBody(req, PRE_AUTH_DRAIN_BYTES);
      sendFixed(res, 400, "");
      return;
    }
    if (pathname === "/healthz") {
      discardBody(req, PRE_AUTH_DRAIN_BYTES);
      if (req.method !== "GET" && req.method !== "HEAD") {
        sendFixed(res, 405, "", { Allow: "GET, HEAD" });
        return;
      }
      res.writeHead(200, { "Content-Type": "text/plain", "Content-Length": "2" });
      res.end(req.method === "HEAD" ? undefined : "ok");
      return;
    }
    if (oauth && !closing && oauth.handles(pathname)) {
      void oauth.handle(req, res, pathname);
      return;
    }
    if (pathname !== "/mcp" || closing) {
      discardBody(req, PRE_AUTH_DRAIN_BYTES);
      sendFixed(res, 404, "");
      return;
    }
    handleMcp(req, res, pathname).catch((e) => {
      if (e instanceof HttpError) {
        discardBody(req, PRE_AUTH_STATUSES.has(e.status) ? PRE_AUTH_DRAIN_BYTES : limits.maxBodyBytes * 2);
        sendFixed(res, e.status, e.body, e.headers);
        return;
      }
      log(`${new Date().toISOString()} request failed (${clean(e instanceof Error ? e.name : "error", 32)})`);
      discardBody(req, PRE_AUTH_DRAIN_BYTES);
      sendFixed(res, 500, BODY_INTERNAL);
    });
  };

  if (publicUrl) {
    oauth = createOAuthEndpoints({
      vaultPath,
      publicUrl,
      redirectUris: [...new Set([...DEFAULT_OAUTH_REDIRECTS, ...(opts.oauth?.redirectUris ?? [])])],
      allowedOrigins,
      authLimiter: limiter,
      /* Counts refused registrations only: a valid one stores nothing and must always pass. */
      registerLimiter: new FailLimiter(20, 60 * 60 * 1000, limits.rateLimitEntries),
      clientKey: (req) => rateKey(clientIp(req)),
      discard: discardBody,
      clean,
      log,
      onGrantRevoked: enforceRevocations,
    });
  }

  /* Node enforces requestTimeout only on this tick; the 30 s default lets a slow client hold a socket that long. */
  const serverOptions = { maxHeaderSize: 16 * 1024, connectionsCheckingInterval: 2_000 };
  const server = tlsOptions
    ? createHttpsServer({ ...tlsOptions, minVersion: "TLSv1.2", ...serverOptions }, onRequest)
    : createHttpServer(serverOptions, onRequest);
  /* Slow-loris: headers and the whole request body must arrive in bounded time. SSE responses are not affected. */
  server.headersTimeout = limits.headersTimeoutMs;
  server.requestTimeout = limits.requestTimeoutMs;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 64;
  server.maxConnections = 256;

  const onSignal = (): void => {
    log(`${new Date().toISOString()} shutting down`);
    void close().finally(() => process.exit(0));
  };

  const close = (): Promise<void> => {
    if (closing) return closing;
    closing = new Promise<void>((resolve) => {
      clearInterval(sweepTimer);
      if (opts.handleSignals !== false) {
        process.off("SIGINT", onSignal);
        process.off("SIGTERM", onSignal);
      }
      for (const s of [...sessions.values()]) closeSession(s, "shutdown");
      oauth?.close();
      limiter.clear();
      server.close(() => resolve());
      server.closeAllConnections();
    });
    return closing;
  };

  return new Promise<HttpServerHandle>((resolve, reject) => {
    const onListenError = (e: Error): void => {
      clearInterval(sweepTimer);
      reject(e);
    };
    server.once("error", onListenError);
    server.listen(port, host, () => {
      server.off("error", onListenError);
      server.on("error", (e: NodeJS.ErrnoException) => log(`${new Date().toISOString()} server error (${clean(e.code ?? e.name, 32)})`));
      if (opts.handleSignals !== false) {
        process.on("SIGINT", onSignal);
        process.on("SIGTERM", onSignal);
      }
      const addr = server.address();
      const boundPort = typeof addr === "object" && addr ? addr.port : port;
      if (!useTls && !isLoopbackHost(host)) {
        log("!!! WARNING: serving PLAIN HTTP on a non-loopback address. Device tokens and SSH output cross the network unencrypted.");
        log("!!! Only do this inside a private network behind a TLS-terminating reverse proxy (see docs/remote.md).");
      }
      if (isLoopbackHost(host) && !opts.trustProxy) {
        log("note: behind a local reverse proxy, pass --trust-proxy so the failed-auth limit counts clients, not the proxy.");
      }
      log(`mcp-sshpilot remote: listening on ${useTls ? "https" : "http"}://${host.includes(":") ? `[${host}]` : host}:${boundPort}/mcp`);
      resolve({ port: boundPort, close });
    });
  });
}
