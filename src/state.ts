import { rmSync } from "fs";
import type { Socket } from "net";
import type { Client } from "ssh2";
import { detach } from "./utils.js";
import { TEMP_DIR, cleanupAllTempFiles } from "./temp.js";
import type { ProfileStore } from "./config.js";
import type {
  SSHSession,
  PendingConfirmation,
  PendingDeleteConfirmation,
  BackgroundJob,
  ProxyOverride,
  LogEntry,
  LastConnect,
  TempFile,
} from "./types.js";

export const DEFAULT_EXEC_TIMEOUT_MS = 5 * 60 * 1000;
export const DEFAULT_KEEPALIVE_MS = 10_000;
export const DEFAULT_READY_TIMEOUT_MS = 30_000;

export const DEFAULT_SFTP_TIMEOUT_MS = 60_000;
export const DEFAULT_TRANSFER_TIMEOUT_MS = 10 * 60 * 1000;
export const CONFIRMATION_TTL_MS = 10 * 60 * 1000;

const CLOSE_GRACE_MS = 2_000;
const MAX_LOG_ENTRIES = 500;
const MAX_LOG_ENTRY_CHARS = 4096;

export type SessionMode = "stdio" | "remote";

/** Open connections per ctx. stdio: every subagent of one client session shares the process. */
export const STDIO_MAX_CONNECTIONS = 16;
/** Remote mode: connections per HTTP session (a device has up to 4 sessions). */
export const REMOTE_MAX_CONNECTIONS = 4;

/** One SSH connection of a ctx, keyed by profile name (or user@host:port for a raw ssh_connect). */
export interface Conn {
  ctx: SessionCtx;
  /** Profile name as saved, or user@host:port; shown to the agent and tagged on log entries. */
  name: string;
  /** "profile:<lower-cased name>" or "raw:<user>@<lower-cased host>:<port>"; the prefixes keep the kinds apart. */
  key: string;
  /** user@host:port of the last dial started, so a call knows where it went even when that dial failed. */
  endpoint?: string;
  session: SSHSession | null;
  lastConnect: LastConnect | null;
  /** Bumped by every connect, disconnect and deadline; a handshake finishing under an older value is discarded. */
  gen: number;
  /** In-flight connect or reconnect; parallel calls wait for it instead of dialing again. */
  connecting: Promise<string> | null;
}

/** Everything one MCP client session owns. stdio mode has one per process; remote mode one per HTTP session. */
export interface SessionCtx {
  connections: Map<string, Conn>;
  logs: LogEntry[];
  pendingConfirmations: Map<string, PendingConfirmation>;
  pendingDeleteConfirmations: Map<string, PendingDeleteConfirmation>;
  /** Ids of confirmations dropped by the pending cap (bounded), so confirming one says why it is gone. */
  droppedConfirmations: Set<string>;
  backgroundJobs: Map<string, BackgroundJob>;
  proxyOverride: ProxyOverride;
  tempFiles: Map<string, TempFile>;
  /** Directory for downloaded temp files; null until first use when the ctx owns a private one (remote mode). */
  tempDir: string | null;
  /** True when tempDir was created for this ctx alone and is removed with it. */
  ownsTempDir: boolean;
  store: ProfileStore;
  mode: SessionMode;
  deviceId?: string;
  /** Connector (OAuth grant) session: only the grant's profiles, no tools that change saved profiles or proxies. */
  scoped: boolean;
  /** Remote mode only: lets profiles and proxies point at loopback/link-local addresses of the MCP host. */
  allowLocalTargets: boolean;
  /** Remote mode only: a profile without a pinned host key may pin it on first connect (serve --allow-tofu). */
  allowTofu: boolean;
  /** Remote mode: bytes of whole-file reads still in flight, so parallel calls cannot multiply the per-call caps. */
  inflight: { inline: number; temp: number };
  destroyed: boolean;
}

export interface CreateCtxOptions {
  store: ProfileStore;
  mode?: SessionMode;
  deviceId?: string;
  scoped?: boolean;
  allowLocalTargets?: boolean;
  /** Remote mode: trust an unpinned profile's host key on first connect. Default false (refused). */
  allowTofu?: boolean;
  /** Overrides the temp directory. Default: the shared TEMP_DIR in stdio mode, a private mkdtemp dir in remote mode. */
  tempDir?: string;
}

export function createCtx(opts: CreateCtxOptions): SessionCtx {
  const mode = opts.mode ?? "stdio";
  return {
    connections: new Map(),
    logs: [],
    pendingConfirmations: new Map(),
    pendingDeleteConfirmations: new Map(),
    droppedConfirmations: new Set(),
    backgroundJobs: new Map(),
    proxyOverride: { mode: "config" },
    tempFiles: new Map(),
    tempDir: opts.tempDir ?? (mode === "stdio" ? TEMP_DIR : null),
    ownsTempDir: false,
    store: opts.store,
    mode,
    deviceId: opts.deviceId,
    scoped: opts.scoped === true,
    allowLocalTargets: opts.allowLocalTargets === true,
    allowTofu: opts.allowTofu === true,
    inflight: { inline: 0, temp: 0 },
    destroyed: false,
  };
}

/** Key of a profile connection; profiles are looked up case-insensitively. */
export function connKey(name: string): string {
  return `profile:${name.toLowerCase()}`;
}

/** Closes one connection and forgets it. Voids a handshake still in flight: its 'ready' handler sees a stale
 * generation and ends the client. */
export function closeConn(conn: Conn): void {
  conn.gen++;
  conn.lastConnect = null;
  conn.connecting = null;
  if (conn.session) {
    closeClient(conn.session.client);
    conn.session = null;
  }
  if (conn.ctx.connections.get(conn.key) === conn) conn.ctx.connections.delete(conn.key);
}

/** Ends every SSH connection, kills background jobs, removes temp files and drops every secret the ctx holds. Idempotent. */
export function destroyCtx(ctx: SessionCtx): void {
  if (ctx.destroyed) return;
  ctx.destroyed = true;
  for (const job of ctx.backgroundJobs.values()) {
    if (job.done) continue;
    try {
      if (typeof job.stream?.signal === "function") job.stream.signal("KILL");
    } catch { /* channel gone */ }
    try {
      if (typeof job.stream?.close === "function") job.stream.close();
    } catch { /* channel gone */ }
  }
  ctx.backgroundJobs.clear();
  for (const conn of [...ctx.connections.values()]) closeConn(conn);
  ctx.connections.clear();
  ctx.logs.length = 0;
  cleanupAllTempFiles(ctx);
  ctx.tempFiles.clear();
  if (ctx.ownsTempDir && ctx.tempDir) {
    try {
      rmSync(ctx.tempDir, { recursive: true, force: true });
    } catch { /* best effort */ }
  }
  ctx.pendingConfirmations.clear();
  ctx.pendingDeleteConfirmations.clear();
  ctx.droppedConfirmations.clear();
  ctx.proxyOverride = { mode: "config" };
  try {
    ctx.store.dispose?.();
  } catch { /* best effort */ }
}

/** Ends the connection and, after a grace period, destroys its socket. end() only half-closes: a peer that never
 * closes its side keeps the socket, its channels and their pending SFTP requests (and read reservations) alive,
 * and ssh2's destroy() is a no-op once end() ran, hence the socket itself. */
export function closeClient(client: Client): void {
  try {
    client.end();
  } catch { /* already gone */ }
  const sock = (client as unknown as { _sock?: Socket })._sock;
  if (!sock || sock.destroyed) return;
  setTimeout(() => { if (!sock.destroyed) sock.destroy(); }, CLOSE_GRACE_MS).unref();
}

/** Session log; entries about one connection (pass the Conn) are tagged with its name. */
export function addLog(target: SessionCtx | Conn, type: LogEntry["type"], content: string): void {
  const conn = "ctx" in target ? target : undefined;
  const ctx = conn ? conn.ctx : (target as SessionCtx);
  if (ctx.destroyed) return;
  const logs = ctx.logs;
  const text = content.length > MAX_LOG_ENTRY_CHARS ? detach(content.slice(0, MAX_LOG_ENTRY_CHARS)) + "...[trimmed]" : content;
  logs.push({ timestamp: new Date(), type, content: conn ? `[${conn.name}] ${text}` : text, conn: conn?.name, connKey: conn?.key });
  if (logs.length > MAX_LOG_ENTRIES) logs.splice(0, logs.length - MAX_LOG_ENTRIES);
}
