import type { IncomingMessage, ServerResponse } from "http";
import { randomBytes, timingSafeEqual } from "crypto";
import { CONSENT_STYLE_SRC, LIFETIME_DAYS, errorPage, selectPage, tokenPage, type ConsentContext, type ProfileChoice } from "./consent.js";
import {
  authenticate,
  createGrant,
  deviceExists,
  getClient,
  isGrantLabel,
  profileDigest,
  readProfiles,
  redeemCode,
  redirectHash,
  refreshGrant,
  registerClient,
  type ClientInfo,
  type GrantTokenResult,
} from "./vault.js";
import { plainText } from "./utils.js";
/** Redirect URIs accepted by default: Claude's connector callbacks (exact match). */
export const DEFAULT_OAUTH_REDIRECTS: string[] = ["https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback"];
const REGISTER_BODY_MAX = 16 * 1024;
const FORM_BODY_MAX = 64 * 1024;
const PENDING_TTL_MS = 5 * 60 * 1000;
const MAX_PENDING = 16;
const MAX_STATE = 512;
const MAX_PARAM = 2048;
const MAX_REDIRECTS_PER_CLIENT = 8;
const DAY_MS = 24 * 60 * 60 * 1000;
const DEFAULT_LIFETIME_DAYS = 30;
const METADATA_CACHE = "public, max-age=300";
const METADATA_DRAIN = 16 * 1024;
/* No client-id key in the vault (an old copy put back while serving): the owner's next `serve --oauth` adds one. */
const REGISTER_UNAVAILABLE_RETRY_S = "300";
/* Unexpected failures are logged at most once per interval: anonymous requests can repeat one (an unreadable vault)
 * at any rate. */
const FAILURE_LOG_INTERVAL_MS = 60_000;
const PRM_PATHS = new Set(["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]);
const ASM_PATH = "/.well-known/oauth-authorization-server";
const PATHS = new Set([...PRM_PATHS, ASM_PATH, "/oauth/register", "/oauth/authorize", "/oauth/token"]);
const AUTH_PARAMS = ["client_id", "redirect_uri", "response_type", "code_challenge", "code_challenge_method", "state", "resource", "scope"];
const TOKEN_PARAMS = ["grant_type", "code", "code_verifier", "redirect_uri", "client_id", "refresh_token", "resource"];

interface Gate {
  retryAfter(key: string, now: number): number;
  /** Counts one failure (or attempt); true when it is the one that blocks the client. */
  fail(key: string, now: number): boolean;
}

export interface OAuthDeps {
  vaultPath: string;
  /** Normalized origin from --public-url: the issuer, and <publicUrl>/mcp is the resource. */
  publicUrl: string;
  redirectUris: string[];
  /** --allowed-origin list: the generic Origin rule for /oauth/register and /oauth/token. */
  allowedOrigins: Set<string>;
  /** The /mcp failed-auth limiter: wrong device tokens on the consent page and failed token requests count there. */
  authLimiter: Gate;
  registerLimiter: Gate;
  clientKey(req: IncomingMessage): string;
  discard(req: IncomingMessage, limit: number): void;
  clean(s: unknown, max?: number): string;
  log(line: string): void;
  /** A grant was revoked (replayed code or refresh token): live sessions must end now, not at the next sweep. */
  onGrantRevoked(): void;
}

export interface OAuthEndpoints {
  handles(pathname: string): boolean;
  handle(req: IncomingMessage, res: ServerResponse, pathname: string): Promise<void>;
  sweep(): void;
  close(): void;
}

interface AuthRequest {
  client: ClientInfo;
  redirectUri: string;
  codeChallenge: string;
  state: string | undefined;
  resource?: string;
  echo: Record<string, string | undefined>;
}

type AuthCheck =
  | { kind: "page"; status: number; title: string; message: string }
  | { kind: "redirect"; redirectUri: string; state: string | undefined; error: string }
  | { kind: "ok"; req: AuthRequest };

interface Pending {
  id: string;
  csrf: string;
  dek: Buffer;
  deviceId: string;
  deviceName: string;
  req: AuthRequest;
  names: string[];
  digests: string[];
  expires: number;
}

class OAuthHttpError extends Error {
  constructor(
    readonly status: number,
    readonly headers: Record<string, string> = {},
  ) {
    super(`HTTP ${status}`);
  }
}
function isLoopbackName(h: string): boolean {
  const n = h.replace(/^\[|\]$/g, "").toLowerCase();
  return n === "localhost" || n === "::1" || /^127\.\d+\.\d+\.\d+$/.test(n);
}
/** --public-url: https origin (http only for loopback, i.e. tests), no path, query, fragment or credentials. */
export function normalizePublicUrl(raw: string): string {
  let u: URL;
  try {
    u = new URL(raw);
  }
  catch {
    throw new Error("--public-url must be an absolute URL such as https://mcp.example.com");
  }
  if (u.username || u.password || u.search || u.hash || (u.pathname !== "/" && u.pathname !== "")) {
    throw new Error("--public-url must be an origin only (https://host[:port]), without path, query or credentials");
  }
  if (u.protocol !== "https:" && !(u.protocol === "http:" && isLoopbackName(u.hostname))) {
    throw new Error("--public-url must use https (plain http is accepted only for localhost)");
  }
  return u.origin;
}
/** --oauth-redirect: absolute https URI (http only for loopback), no fragment. Compared verbatim later. */
export function checkRedirectUri(raw: string): string {
  let u: URL;
  try {
    u = new URL(raw);
  }
  catch {
    throw new Error("--oauth-redirect must be an absolute URL");
  }
  if (u.hash || raw.includes("#") || u.username || u.password)
    throw new Error("--oauth-redirect must not contain a fragment or credentials");
  if (u.protocol !== "https:" && !(u.protocol === "http:" && isLoopbackName(u.hostname))) {
    throw new Error("--oauth-redirect must use https (plain http is accepted only for localhost)");
  }
  if (raw.length > MAX_PARAM)
    throw new Error("--oauth-redirect is too long");
  return raw;
}
/* "registered 40 seconds ago": lets the owner tell a client Claude just registered from an old or foreign one. */
function ago(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  const [n, unit] = s < 120 ? [s, "second"] : s < 7200 ? [Math.floor(s / 60), "minute"] : s < 172800 ? [Math.floor(s / 3600), "hour"] : [Math.floor(s / 86400), "day"];
  return `${n} ${unit}${n === 1 ? "" : "s"} ago`;
}
function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a, "utf-8");
  const y = Buffer.from(b, "utf-8");
  return x.length === y.length && timingSafeEqual(x, y);
}
/* The grant label offered by default: the client's name, unless it looks like a grant id or a token. */
function defaultLabel(clientName: string): string {
  const l = plainText(clientName, 64);
  return isGrantLabel(l) ? l : "Claude connector";
}
function headerValue(req: IncomingMessage, name: string): string | undefined {
  const v = req.headers[name];
  return Array.isArray(v) ? v.join(", ") : v;
}
function readLimited(req: IncomingMessage, max: number): Promise<Buffer> {
  const declared = Number(req.headers["content-length"]);
  if (Number.isFinite(declared) && declared > max)
    return Promise.reject(new OAuthHttpError(413));
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    const done = (err?: OAuthHttpError): void => {
      req.off("data", onData);
      req.off("end", onEnd);
      req.off("error", onError);
      req.off("aborted", onError);
      if (err)
        reject(err);
      else
        resolve(Buffer.concat(chunks, total));
    };
    const onData = (c: Buffer): void => {
      total += c.length;
      if (total > max) {
        chunks.length = 0;
        req.pause();
        done(new OAuthHttpError(413));
        return;
      }
      chunks.push(c);
    };
    const onEnd = () => done();
    const onError = () => done(new OAuthHttpError(400));
    req.on("data", onData);
    req.on("end", onEnd);
    req.on("error", onError);
    req.on("aborted", onError);
  });
}
async function readBody(req: IncomingMessage, type: RegExp, max: number): Promise<string> {
  if (!type.test((headerValue(req, "content-type") ?? "").trim()))
    throw new OAuthHttpError(415);
  const enc = headerValue(req, "content-encoding");
  if (enc && enc.toLowerCase() !== "identity")
    throw new OAuthHttpError(415);
  const raw = await readLimited(req, max);
  try {
    return raw.toString("utf-8");
  }
  finally {
    raw.fill(0);
  }
}
const readForm = async (req: IncomingMessage): Promise<URLSearchParams> => new URLSearchParams(await readBody(req, /^application\/x-www-form-urlencoded\s*(;|$)/i, FORM_BODY_MAX));
function duplicated(q: URLSearchParams, names: string[]): string | undefined {
  return names.find((n) => q.getAll(n).length > 1);
}
function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": String(Buffer.byteLength(text)),
    "Cache-Control": "no-store",
    Pragma: "no-cache",
    ...headers,
  });
  res.end(text);
}
const oauthError = (res: ServerResponse, status: number, error: string, headers: Record<string, string> = {}): void => sendJson(res, status, { error }, headers);
/* form-action must name the redirect target too: browsers check the redirect that follows a form POST against it. */
function sendPage(res: ServerResponse, status: number, html: string, redirectOrigin?: string, headers: Record<string, string> = {}): void {
  const formAction = redirectOrigin ? `'self' ${redirectOrigin}` : "'self'";
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": String(Buffer.byteLength(html)),
    "Content-Security-Policy": `default-src 'none'; style-src ${CONSENT_STYLE_SRC}; form-action ${formAction}; frame-ancestors 'none'; base-uri 'none'`,
    "X-Frame-Options": "DENY",
    /* Not no-referrer: with it browsers send "Origin: null" on the form POST, which the Origin check must refuse. */
    "Referrer-Policy": "same-origin",
    "Cache-Control": "no-store",
    ...headers,
  });
  res.end(html);
}
function sendRedirect(res: ServerResponse, target: string, params: Record<string, string | undefined>): void {
  const u = new URL(target);
  for (const [k, v] of Object.entries(params))
    if (v !== undefined)
      u.searchParams.append(k, v);
  res.writeHead(302, { Location: u.href, "Referrer-Policy": "no-referrer", "Cache-Control": "no-store", "Content-Length": "0" });
  res.end();
}
export function createOAuthEndpoints(d: OAuthDeps): OAuthEndpoints {
  const pub = d.publicUrl;
  const resource = `${pub}/mcp`;
  const serverHost = new URL(pub).host;
  const allowlist = new Set(d.redirectUris);
  const pendings = new Map<string, Pending>();
  const now = () => Date.now();
  const ts = () => new Date().toISOString();
  const prm = JSON.stringify({
    resource,
    authorization_servers: [pub],
    bearer_methods_supported: ["header"],
    resource_name: "mcp-sshpilot",
  });
  const asm = JSON.stringify({
    issuer: pub,
    authorization_endpoint: `${pub}/oauth/authorize`,
    token_endpoint: `${pub}/oauth/token`,
    registration_endpoint: `${pub}/oauth/register`,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    /* RFC 9207: every authorization response names its issuer, so a client can detect a mix-up with another AS. */
    authorization_response_iss_parameter_supported: true,
  });
  /* RFC 8707 resource: this server's /mcp only. Scheme and host compare case-insensitively (URL lowercases them). */
  const resourceOk = (r: string): boolean => {
    try {
      const u = new URL(r);
      return !u.search && !u.hash && !r.includes("#") && u.origin === pub && (u.pathname === "/mcp" || u.pathname === "/mcp/");
    }
    catch {
      return false;
    }
  };
  const redirect = (res: ServerResponse, target: string, params: Record<string, string | undefined>): void => sendRedirect(res, target, { ...params, iss: pub });
  const drop = (p: Pending): void => {
    pendings.delete(p.id);
    p.dek.fill(0);
  };
  /* A pending consent holds the main vault key: it goes as soon as its device is revoked (or the vault is unreadable). */
  const deviceGone = (p: Pending): boolean => {
    try {
      return !deviceExists(d.vaultPath, p.deviceId);
    }
    catch {
      return true;
    }
  };
  /* Grant pruning is the server's own sweep (http.ts): grants stay in the file when --oauth is off too. */
  const sweep = () => {
    const t = now();
    for (const p of [...pendings.values()])
      if (p.expires <= t || deviceGone(p))
        drop(p);
  };
  const onRevoke = (grantId: string): void => {
    d.log(`${ts()} oauth grant revoked grant=${grantId} reason=token-replay`);
    d.onGrantRevoked();
  };
  /* Unknown refresh tokens that would revoke their grant but met a vault lock another process held: tried again by
   * every sweep until the lock is free. Waiting in the request instead would let anyone who knows a grant id and its
   * client id tie up the server. One entry per grant in the file, so the map stays small and no request can crowd
   * out another's revocation (any entry for a grant revokes that grant). */
  const deferred = new Map<string, { token: string; clientId: string }>();
  const revokeDeferred = () => {
    for (const [grantId, r] of [...deferred]) {
      try {
        if (!refreshGrant(d.vaultPath, r.token, r.clientId, onRevoke).busy)
          deferred.delete(grantId);
      }
      catch {
        /* Unreadable vault: tried again at the next sweep. */
      }
    }
  };
  const consentCtx = (r: AuthRequest): ConsentContext => ({
    clientName: r.client.name,
    clientId: r.client.id.slice(0, 8),
    registered: ago(now() - Date.parse(r.client.createdAt)),
    redirectHost: new URL(r.redirectUri).host,
    serverHost,
  });
  const checkAuthRequest = (q: URLSearchParams): AuthCheck => {
    const page = (title: string, message: string): AuthCheck => ({ kind: "page", status: 400, title, message });
    const dup = duplicated(q, AUTH_PARAMS);
    if (dup)
      return page("Invalid request", `The parameter ${dup} appears more than once.`);
    const clientId = q.get("client_id") ?? "";
    const client = clientId.length <= MAX_PARAM ? getClient(d.vaultPath, clientId) : null;
    if (!client)
      return page("Unknown client", "This client is not registered with this server. Remove the connector and add it again.");
    const redirectUri = q.get("redirect_uri") ?? "";
    /* Never redirect to an address that is not both registered by this client and still on the allowlist. */
    if (!allowlist.has(redirectUri) || !client.redirectHashes.includes(redirectHash(redirectUri))) {
      return page("Invalid redirect address", "The redirect address does not match one this client registered on this server.");
    }
    const state = q.get("state") ?? undefined;
    if (state !== undefined && state.length > MAX_STATE)
      return page("Invalid request", "The state parameter is too long.");
    const fail = (error: string): AuthCheck => ({ kind: "redirect", redirectUri, state, error });
    if (q.get("response_type") !== "code")
      return fail("unsupported_response_type");
    const codeChallenge = q.get("code_challenge") ?? "";
    if (q.get("code_challenge_method") !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(codeChallenge))
      return fail("invalid_request");
    const asked = q.get("resource") ?? undefined;
    if (asked !== undefined && !resourceOk(asked))
      return fail("invalid_target");
    const echo: Record<string, string | undefined> = {};
    for (const k of AUTH_PARAMS)
      if (k !== "scope")
        echo[k] = q.get(k) ?? undefined;
    return { kind: "ok", req: { client, redirectUri, codeChallenge, state, ...(asked !== undefined ? { resource } : {}), echo } };
  };
  /* Answers an invalid request; true when it did. */
  const answerInvalid = (res: ServerResponse, c: AuthCheck): boolean => {
    if (c.kind === "page") {
      sendPage(res, c.status, errorPage(c.title, c.message));
      return true;
    }
    if (c.kind === "redirect") {
      redirect(res, c.redirectUri, { error: c.error, state: c.state });
      return true;
    }
    return false;
  };
  const renderSelect = (
    res: ServerResponse,
    p: Pending,
    status: number,
    form: { label: string; lifetimeDays: number },
    selected: Set<string>,
    error?: string,
  ): void => {
    const servers = readProfiles(d.vaultPath, p.dek).servers;
    const choices: ProfileChoice[] = servers.map((s) => ({
      name: s.name,
      target: `${s.username}@${s.host}:${s.port || 22}`,
      ...(s.description ? { description: s.description } : {}),
    }));
    p.names = choices.map((c) => c.name);
    p.digests = servers.map(profileDigest);
    /* The form posts indices into the list it showed: a form from an earlier render must not land in this one. */
    p.csrf = randomBytes(32).toString("base64url");
    const html = selectPage(consentCtx(p.req), { pending: p.id, csrf: p.csrf, label: form.label, lifetimeDays: form.lifetimeDays, deviceName: p.deviceName }, choices, selected, error);
    sendPage(res, status, html, new URL(p.req.redirectUri).origin);
  };
  const authorizeGet = (req: IncomingMessage, res: ServerResponse): void => {
    const q = new URL(req.url ?? "/", "http://localhost").searchParams;
    const c = checkAuthRequest(q);
    if (answerInvalid(res, c))
      return;
    const r = (c as Extract<AuthCheck, { kind: "ok" }>).req;
    sendPage(res, 200, tokenPage(consentCtx(r), r.echo), new URL(r.redirectUri).origin);
  };
  const authorizeToken = (req: IncomingMessage, res: ServerResponse, form: URLSearchParams): void => {
    const c = checkAuthRequest(form);
    if (answerInvalid(res, c))
      return;
    const r = (c as Extract<AuthCheck, { kind: "ok" }>).req;
    const origin = new URL(r.redirectUri).origin;
    if (duplicated(form, ["device_token"]))
      throw new OAuthHttpError(400);
    /* authenticate() takes device tokens only: the recovery key is refused like any wrong token. As on /mcp the
     * failed-auth limiter answers failures only; a valid token always passes. */
    const auth = authenticate(d.vaultPath, (form.get("device_token") ?? "").trim());
    if (!auth) {
      const key = d.clientKey(req);
      const wait = d.authLimiter.retryAfter(key, now());
      if (wait > 0) {
        sendPage(res, 429, tokenPage(consentCtx(r), r.echo, `Too many failed attempts from this network. Try again in ${Math.ceil(wait / 60)} min.`), origin, { "Retry-After": String(wait) });
        return;
      }
      if (d.authLimiter.fail(key, now()))
        d.log(`${ts()} auth blocked ip=${d.clean(key)} (consent page)`);
      sendPage(res, 401, tokenPage(consentCtx(r), r.echo, "That device token was not accepted."), origin);
      return;
    }
    const p: Pending = {
      id: randomBytes(32).toString("base64url"),
      csrf: randomBytes(32).toString("base64url"),
      dek: auth.dek,
      deviceId: auth.deviceId,
      deviceName: auth.deviceName,
      req: r,
      names: [],
      digests: [],
      expires: now() + PENDING_TTL_MS,
    };
    sweep();
    /* Map order is insertion order: the oldest pending consent makes room. */
    for (const oldest of [...pendings.values()]) {
      if (pendings.size < MAX_PENDING)
        break;
      drop(oldest);
    }
    pendings.set(p.id, p);
    try {
      renderSelect(res, p, 200, { label: defaultLabel(r.client.name), lifetimeDays: DEFAULT_LIFETIME_DAYS }, new Set());
    }
    catch (e) {
      drop(p);
      throw e;
    }
  };
  const authorizeDecision = (res: ServerResponse, form: URLSearchParams): void => {
    const p = pendings.get(form.get("pending") ?? "");
    /* A device revoked meanwhile takes its approvals in progress along: no profile list, no grant. */
    if (!p || p.expires <= now() || deviceGone(p)) {
      if (p)
        drop(p);
      sendPage(res, 400, errorPage("Approval expired", "This approval page has expired (after 5 minutes) or was already used."));
      return;
    }
    if (duplicated(form, ["pending", "csrf", "action", "label", "lifetime"]) || !safeEqual(form.get("csrf") ?? "", p.csrf)) {
      drop(p);
      sendPage(res, 403, errorPage("Request refused", "The approval form did not come from this page."));
      return;
    }
    const action = form.get("action");
    if (action === "deny") {
      drop(p);
      redirect(res, p.req.redirectUri, { error: "access_denied", state: p.req.state });
      return;
    }
    if (action !== "grant") {
      drop(p);
      sendPage(res, 400, errorPage("Invalid request", "Unknown action."));
      return;
    }
    /* Indices, not names: a full list of long names would not fit the form body cap. */
    const picked = [...new Set(form.getAll("profile"))];
    const indices = picked.flatMap((i) => (/^(?:0|[1-9]\d{0,3})$/.test(i) && Number(i) < p.names.length ? [Number(i)] : []));
    const names = indices.map((i) => p.names[i]);
    const label = plainText(form.get("label"), 64) || defaultLabel(p.req.client.name);
    const days = Number(form.get("lifetime"));
    const lifetimeDays = (LIFETIME_DAYS as readonly number[]).includes(days) ? days : DEFAULT_LIFETIME_DAYS;
    const error = names.length !== picked.length ? "The profile list changed; choose again." :
      names.length === 0 ? "Choose at least one profile." :
        !isGrantLabel(label) ? "The label must not look like a grant id or a token." :
          !(LIFETIME_DAYS as readonly number[]).includes(days) ? "Choose an expiry from the list." : undefined;
    if (error) {
      try {
        renderSelect(res, p, 400, { label, lifetimeDays }, new Set(names), error);
      }
      catch (e) {
        drop(p);
        throw e;
      }
      return;
    }
    let created: { grantId: string; code: string };
    try {
      created = createGrant(d.vaultPath, {
        dek: p.dek,
        deviceId: p.deviceId,
        client: p.req.client,
        label,
        lifetimeMs: lifetimeDays * DAY_MS,
        profiles: indices.map((i) => ({ name: p.names[i], digest: p.digests[i] })),
        code: { redirectUri: p.req.redirectUri, codeChallenge: p.req.codeChallenge, ...(p.req.resource ? { resource: p.req.resource } : {}) },
      });
    }
    catch (e) {
      drop(p);
      sendPage(res, 409, errorPage("Not approved", e instanceof Error ? e.message : "The grant could not be created."));
      return;
    }
    drop(p);
    d.log(`${ts()} oauth grant created grant=${created.grantId} label=${d.clean(label)} client=${p.req.client.id.slice(0, 8)} profiles=${names.length} device=${d.clean(p.deviceName)}`);
    redirect(res, p.req.redirectUri, { code: created.code, state: p.req.state });
  };
  const authorize = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    if (req.method === "GET") {
      d.discard(req, METADATA_DRAIN);
      authorizeGet(req, res);
      return;
    }
    if (req.method !== "POST")
      throw new OAuthHttpError(405, { Allow: "GET, POST" });
    /* A browser always sends Origin on a form POST; only this server's own pages may post here. */
    if (headerValue(req, "origin") !== pub) {
      d.discard(req, FORM_BODY_MAX);
      sendPage(res, 403, errorPage("Request refused", "This form can only be submitted from this server's own page."));
      return;
    }
    let form: URLSearchParams;
    try {
      form = await readForm(req);
    }
    catch (e) {
      if (!(e instanceof OAuthHttpError) || e.status !== 413)
        throw e;
      /* Drained a little past the cap, so a browser that overshot reads the page instead of a reset. */
      d.discard(req, 2 * FORM_BODY_MAX);
      sendPage(res, 413, errorPage("Request too large", "The form was larger than this server accepts."));
      return;
    }
    if (form.has("pending"))
      authorizeDecision(res, form);
    else
      authorizeToken(req, res, form);
  };
  /* Origin rule of /mcp: no Origin (server-side clients) or one listed with --allowed-origin. */
  const checkOrigin = (req: IncomingMessage): void => {
    const origin = headerValue(req, "origin");
    if (origin !== undefined && !d.allowedOrigins.has(origin.trim().toLowerCase()))
      throw new OAuthHttpError(403);
  };
  const register = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    if (req.method !== "POST")
      throw new OAuthHttpError(405, { Allow: "POST" });
    checkOrigin(req);
    /* Only refusals count, like the failed-auth limiter: a valid registration stores nothing (the client id is
     * self-contained) and always passes, since connectors share Anthropic's egress addresses. */
    const refuse = (error: OAuthHttpError | string): void => {
      const key = d.clientKey(req);
      const wait = d.registerLimiter.retryAfter(key, now());
      if (wait > 0)
        throw new OAuthHttpError(429, { "Retry-After": String(wait) });
      if (d.registerLimiter.fail(key, now()))
        d.log(`${ts()} oauth registration limit reached ip=${d.clean(key)}`);
      if (error instanceof OAuthHttpError)
        throw error;
      oauthError(res, 400, error);
    };
    let meta: unknown;
    try {
      meta = JSON.parse(await readBody(req, /^application\/json\s*(;|$)/i, REGISTER_BODY_MAX));
    }
    catch (e) {
      return refuse(e instanceof OAuthHttpError ? e : "invalid_client_metadata");
    }
    if (typeof meta !== "object" || meta === null || Array.isArray(meta))
      return refuse("invalid_client_metadata");
    const m = meta as Record<string, unknown>;
    const uris = m.redirect_uris;
    if (!Array.isArray(uris) || uris.length === 0 || uris.length > MAX_REDIRECTS_PER_CLIENT || !uris.every((u) => typeof u === "string" && allowlist.has(u))) {
      return refuse("invalid_redirect_uri");
    }
    if (m.client_name !== undefined && typeof m.client_name !== "string")
      return refuse("invalid_client_metadata");
    /* Public clients only. Other requested values are replaced by what this server supports (RFC 7591 3.2.1). */
    const name = plainText(m.client_name, 64) || "MCP client";
    const redirectUris = [...new Set(uris)];
    /* Not logged: a registration is anonymous, unlimited and stores nothing; the grant line names its client. */
    const client = registerClient(d.vaultPath, name, redirectUris);
    if (!client)
      throw new OAuthHttpError(503, { "Retry-After": REGISTER_UNAVAILABLE_RETRY_S });
    sendJson(res, 201, {
      client_id: client.id,
      client_id_issued_at: Math.floor(Date.parse(client.createdAt) / 1000),
      client_name: client.name,
      redirect_uris: redirectUris,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    });
  };
  const token = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    if (req.method !== "POST")
      throw new OAuthHttpError(405, { Allow: "POST" });
    checkOrigin(req);
    const form = await readForm(req);
    if (duplicated(form, TOKEN_PARAMS))
      return oauthError(res, 400, "invalid_request");
    const clientId = form.get("client_id") ?? "";
    if (!clientId || clientId.length > MAX_PARAM)
      return oauthError(res, 400, "invalid_request");
    const res8707 = form.get("resource");
    if (res8707 !== null && !resourceOk(res8707))
      return oauthError(res, 400, "invalid_target");
    /* The owner's only trace of a second holder of a refresh token who refreshes in step with the connector. */
    const onRetry = (grantId: string): void => d.log(`${ts()} oauth grant refresh retry grant=${grantId} ip=${d.clean(d.clientKey(req))}`);
    let result: GrantTokenResult;
    switch (form.get("grant_type")) {
      case "authorization_code": {
        const code = form.get("code");
        const verifier = form.get("code_verifier");
        const redirectUri = form.get("redirect_uri");
        if (!code || !verifier || !redirectUri)
          return oauthError(res, 400, "invalid_request");
        result = redeemCode(d.vaultPath, code, { clientId, redirectUri, codeVerifier: verifier, ...(res8707 ? { resource } : {}) }, onRevoke);
        break;
      }
      case "refresh_token": {
        const refresh = form.get("refresh_token");
        if (!refresh)
          return oauthError(res, 400, "invalid_request");
        result = refreshGrant(d.vaultPath, refresh, clientId, onRevoke, onRetry);
        if (result.busy && !deferred.has(result.busy.grantId))
          deferred.set(result.busy.grantId, { token: refresh, clientId });
        break;
      }
      default:
        return oauthError(res, 400, "unsupported_grant_type");
    }
    const tokens = result.tokens;
    /* Like /mcp, the limiter only answers failures: a valid code or refresh token always passes, so whoever shares
     * the connector's egress addresses (Anthropic's cloud) cannot lock the owner's connector out. A refused token
     * the grant recognises (a replay, a retry too late, the wrong client) is a real secret, not a guess: never
     * counted, never answered with 429. */
    if (!tokens) {
      if (!result.recognised) {
        const key = d.clientKey(req);
        const wait = d.authLimiter.retryAfter(key, now());
        if (wait > 0)
          return oauthError(res, 429, "invalid_request", { "Retry-After": String(wait) });
        if (d.authLimiter.fail(key, now()))
          d.log(`${ts()} auth blocked ip=${d.clean(key)} (token endpoint)`);
      }
      return oauthError(res, 400, "invalid_grant");
    }
    sendJson(res, 200, {
      access_token: tokens.accessToken,
      token_type: "Bearer",
      expires_in: tokens.expiresIn,
      refresh_token: tokens.refreshToken,
    });
  };
  const metadata = (req: IncomingMessage, res: ServerResponse, body: string): void => {
    d.discard(req, METADATA_DRAIN);
    if (req.method !== "GET")
      throw new OAuthHttpError(405, { Allow: "GET" });
    res.writeHead(200, { "Content-Type": "application/json", "Content-Length": String(Buffer.byteLength(body)), "Cache-Control": METADATA_CACHE });
    res.end(body);
  };
  let failureLoggedAt = -Infinity;
  let failuresUnlogged = 0;
  const logFailure = (e: unknown): void => {
    const t = now();
    if (t - failureLoggedAt < FAILURE_LOG_INTERVAL_MS) {
      failuresUnlogged++;
      return;
    }
    const more = failuresUnlogged > 0 ? ` (+${failuresUnlogged} since the last line)` : "";
    d.log(`${ts()} oauth request failed (${d.clean(e instanceof Error ? e.name : "error", 32)})${more}`);
    failureLoggedAt = t;
    failuresUnlogged = 0;
  };
  const handle = async (req: IncomingMessage, res: ServerResponse, pathname: string): Promise<void> => {
    try {
      if (PRM_PATHS.has(pathname))
        metadata(req, res, prm);
      else if (pathname === ASM_PATH)
        metadata(req, res, asm);
      else if (pathname === "/oauth/register")
        await register(req, res);
      else if (pathname === "/oauth/authorize")
        await authorize(req, res);
      else
        await token(req, res);
    }
    catch (e) {
      const status = e instanceof OAuthHttpError ? e.status : 500;
      if (!(e instanceof OAuthHttpError))
        logFailure(e);
      d.discard(req, FORM_BODY_MAX);
      if (res.headersSent) {
        res.destroy();
        return;
      }
      const headers = e instanceof OAuthHttpError ? e.headers : {};
      res.writeHead(status, { "Content-Length": "0", "Cache-Control": "no-store", ...headers });
      res.end();
    }
  };
  return {
    handles: (pathname: string) => PATHS.has(pathname),
    handle,
    sweep: () => {
      sweep();
      revokeDeferred();
    },
    close: () => {
      for (const p of [...pendings.values()])
        drop(p);
      deferred.clear();
    },
  };
}
