import { Client, ConnectConfig, SFTPWrapper } from "ssh2";
import type { ProxyConfig, BackgroundJob, LastConnect } from "./types.js";
import {
  addLog,
  closeClient,
  closeConn,
  connKey,
  DEFAULT_EXEC_TIMEOUT_MS,
  DEFAULT_KEEPALIVE_MS,
  DEFAULT_READY_TIMEOUT_MS,
  REMOTE_MAX_CONNECTIONS,
  STDIO_MAX_CONNECTIONS,
} from "./state.js";
import type { Conn, SessionCtx, SessionMode } from "./state.js";
import { getServerProfile, profileToConnectConfig } from "./config.js";
import { createHash, randomBytes } from "crypto";
import { lookup } from "dns/promises";
import { BlockList, isIP } from "net";
import { buildProxySocket, describeProxy, resolveProxyForProfile } from "./proxy.js";
import { detach, generateId, OutputTail } from "./utils.js";
import { listTempFiles, deleteTempFile } from "./temp.js";

const EXEC_OUTPUT_CAP = 1024 * 1024;
const BACKGROUND_OUTPUT_CAP = 256 * 1024;
/* Remote mode keeps finished jobs (and their output) for ssh_read_background, but not without bound. */
const REMOTE_MAX_BACKGROUND_JOBS = 32;
const JOB_COMMAND_DISPLAY_CHARS = 4096;

/* Remote mode: the MCP host is internet-facing and shared, so a profile or proxy must not make it a hop to its own
 * loopback, link-local (cloud metadata) or unspecified addresses. */
const LOCAL_TARGETS = new BlockList();
LOCAL_TARGETS.addSubnet("0.0.0.0", 8, "ipv4");
LOCAL_TARGETS.addSubnet("127.0.0.0", 8, "ipv4");
LOCAL_TARGETS.addSubnet("169.254.0.0", 16, "ipv4");
/* Cloud metadata outside link-local: Alibaba (IPv4) and AWS IMDS over IPv6. */
LOCAL_TARGETS.addAddress("100.100.100.200", "ipv4");
LOCAL_TARGETS.addAddress("::", "ipv6");
LOCAL_TARGETS.addAddress("::1", "ipv6");
LOCAL_TARGETS.addSubnet("fe80::", 10, "ipv6");
LOCAL_TARGETS.addAddress("fd00:ec2::254", "ipv6");

function isLocalTarget(address: string, family: number): boolean {
  try {
    return LOCAL_TARGETS.check(address, family === 6 ? "ipv6" : "ipv4");
  } catch {
    return true;
  }
}

/* Returns the address to dial. The check runs on the resolved addresses and the dialed one is among them, so DNS
 * cannot answer differently between the check and the connect. */
async function connectAddress(ctx: SessionCtx, host: string, what: string): Promise<string> {
  if (ctx.mode !== "remote" || ctx.allowLocalTargets) return host;
  const family = isIP(host);
  const addrs = family ? [{ address: host, family }] : await lookup(host, { all: true, verbatim: true });
  if (addrs.length === 0) throw new Error(`${what} ${host} does not resolve`);
  const local = addrs.find((a) => isLocalTarget(a.address, a.family));
  if (local) {
    throw new Error(
      `${what} ${host} ${local.address === host ? "is" : `resolves to ${local.address},`} a loopback/link-local address of the MCP server itself; ` +
        `refused in remote mode (the operator can allow it with serve --allow-local-targets)`
    );
  }
  return addrs[0].address;
}

/** OpenSSH-style fingerprint of a raw host key blob: "SHA256:" + unpadded base64 of its SHA-256. */
export function hostKeyFingerprint(key: Buffer): string {
  return "SHA256:" + createHash("sha256").update(key).digest("base64").replace(/=+$/, "");
}

/* Accepts "SHA256:<b64>" (any prefix case) or bare base64, padded or not, so a value pasted from ssh-keygen -lf matches. */
export function normalizeHostKeyFingerprint(fp: string): string {
  const b64 = fp.trim().replace(/^sha256:/i, "").replace(/=+$/, "");
  return `SHA256:${b64}`;
}

/* The agent reads this. It must stop rather than re-pin: an agent cannot verify a key out of band, and following
 * a "how to fix" line here would hand the credentials to whoever answered. */
export class HostKeyMismatchError extends Error {
  /** pinned: expected is a profile's pin; otherwise only the key an earlier connect of this session saw.
   * credentialsSent: the pin turned up only after authentication (set meanwhile by another session or a scan). */
  constructor(
    readonly target: string,
    readonly expected: string,
    readonly actual: string,
    mode: SessionMode,
    pinned = true,
    credentialsSent = false
  ) {
    super(
      `HOST KEY MISMATCH for ${target}: ${pinned ? "pinned" : "earlier in this session the server presented"} ${expected}, server presented ${actual}. ` +
        (credentialsSent
          ? `The pin was set while this connection authenticated: the profile's credentials WERE sent to the server presenting ${actual}. ` +
            `Disconnected; nothing was executed. They must be changed on the real server. `
          : `Connection refused before authentication; no credentials were sent and nothing was executed. `) +
        `This is either a man-in-the-middle or a reinstalled/rekeyed server. Do not ${pinned ? "re-pin" : "reconnect"} on your own: stop and ` +
        `tell the user. Only someone who checked the key on the server itself (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub) ` +
        (!pinned
          ? `may accept it; after the user confirms: ssh_disconnect, then connect again (no profile holds this key).`
          : mode === "remote"
            ? `may re-pin it, with \`mcp-sshpilot vault pin-host-key <profile> <SHA256:...>\` on a machine holding a vault unlock key; this server cannot re-pin.`
            : `may re-pin it; after the user confirms: ssh_server_update({name, reset_host_key: true}), then ssh_connect_profile.`)
    );
    this.name = "HostKeyMismatchError";
  }
}

export interface SshConnectOptions {
  /** Pinned "SHA256:<base64>"; any other host key aborts the handshake before authentication. */
  expectedHostKey?: string;
  /** expectedHostKey is a profile's pin (shown by ssh_status), not just the key of an earlier raw connect. */
  pinned?: boolean;
  /** Called with the connection this connect registered or joined, before it dials (a call binds its deadline to it). */
  bind?: (conn: Conn) => void;
  /** Saved profile this connect uses: it names the connection, our copies of its credentials are dropped after the
   * handshake (a reconnect re-reads them from the store by this name), and so is the proxy password. ssh2 itself keeps
   * the parsed key and the password of its last attempt for the client's lifetime. */
  profile?: string;
}

export function maxConnections(ctx: SessionCtx): number {
  return ctx.mode === "remote" ? REMOTE_MAX_CONNECTIONS : STDIO_MAX_CONNECTIONS;
}

/** Name of the connection a raw ssh_connect opens: user@host:port. */
export function rawConnName(config: ConnectConfig): string {
  return `${config.username}@${config.host}:${config.port || 22}`;
}

/* The user name keeps its case (Root is not root); the host does not. */
function rawConnKey(config: ConnectConfig): string {
  return `raw:${config.username}@${String(config.host).toLowerCase()}:${config.port || 22}`;
}

/* user@host:port, split at the last ':' and at the last '@' before it, so IPv6 hosts (u@::1:22) parse too. */
function rawKeyOfName(name: string): string | undefined {
  const colon = name.lastIndexOf(":");
  const at = name.lastIndexOf("@", colon);
  const port = Number(name.slice(colon + 1));
  if (colon < 0 || at <= 0 || at + 1 >= colon || !Number.isInteger(port) || port <= 0) return undefined;
  return rawConnKey({ username: name.slice(0, at), host: name.slice(at + 1, colon), port });
}

/** Every key a name may refer to: the profile of that name, and a raw connection user@host:port. */
export function keysOfName(name: string): string[] {
  const raw = rawKeyOfName(name);
  return raw ? [connKey(name), raw] : [connKey(name)];
}

/** The open connection a name refers to: a profile (case-insensitive), else a raw connection, by its exact name first. */
export function findConn(ctx: SessionCtx, name: string): Conn | undefined {
  const byProfile = ctx.connections.get(connKey(name));
  if (byProfile) return byProfile;
  for (const c of ctx.connections.values()) if (c.key.startsWith("raw:") && c.name === name) return c;
  const raw = rawKeyOfName(name);
  return raw ? ctx.connections.get(raw) : undefined;
}

/** Key a connect of this config would register under. */
export function connectKey(config: ConnectConfig, profile?: string): string {
  return profile !== undefined ? connKey(profile) : rawConnKey(config);
}

function endpointOf(c: { username?: string; host?: string; port?: number }): string {
  return `${c.username}@${c.host}:${c.port || 22}`;
}

function withoutProxyPassword(p: ProxyConfig): ProxyConfig {
  const { password: _p, ...rest } = p;
  return rest;
}

/* Where a proxy leads, credentials aside. */
function proxyRoute(p: ProxyConfig | undefined): string {
  return p ? JSON.stringify([p.type, p.host, p.port, p.username ?? null]) : "direct";
}

function dropSecrets(config: ConnectConfig): void {
  delete config.password;
  delete config.privateKey;
  delete config.passphrase;
}

/** Opens a connection of ctx (or re-opens a dropped one with new parameters). It is registered while it dials, so
 * parallel calls count it against the cap and wait for it instead of dialing the same server again. */
export async function sshConnect(
  ctx: SessionCtx,
  config: ConnectConfig,
  proxy?: ProxyConfig,
  opts: SshConnectOptions = {}
): Promise<{ conn: Conn; message: string; joined?: boolean }> {
  if (ctx.destroyed) throw new Error("Session is closed");
  const name = opts.profile ?? rawConnName(config);
  const key = connectKey(config, opts.profile);
  let conn = ctx.connections.get(key);
  if (conn?.connecting) {
    opts.bind?.(conn);
    await conn.connecting;
    return { conn, message: `✅ Connected to ${name} (by a parallel call)`, joined: true };
  }
  if (conn?.session?.connected) {
    throw new Error(`Already connected to ${name}. Pass profile "${name}" to use it, or ssh_disconnect {profile: "${name}"} first.`);
  }
  if (!conn) {
    const max = maxConnections(ctx);
    if (ctx.connections.size >= max) {
      throw new Error(`${max} connections are already open in this session (${connectionNames(ctx)}); ssh_disconnect one first`);
    }
    conn = { ctx, name, key, session: null, lastConnect: null, gen: 0, connecting: null };
    ctx.connections.set(key, conn);
  } else if (conn.session) {
    closeClient(conn.session.client);
    conn.session = null;
  }
  const c = conn;
  opts.bind?.(c);
  const attempt = dial(c, config, proxy, opts);
  c.connecting = attempt;
  try {
    return { conn: c, message: await attempt };
  } catch (e) {
    /* A first connect that failed leaves nothing to reconnect to. Only while it is still the current attempt: a
     * voided one must not drop the entry a newer attempt is using. */
    if (c.connecting === attempt && !c.session && !c.lastConnect && ctx.connections.get(key) === c) ctx.connections.delete(key);
    throw e;
  } finally {
    if (c.connecting === attempt) c.connecting = null;
  }
}

/** Names of the ctx's connections, for messages. */
export function connectionNames(ctx: SessionCtx): string {
  return [...ctx.connections.values()].map((c) => c.name).join(", ") || "none";
}

async function dial(conn: Conn, config: ConnectConfig, proxy: ProxyConfig | undefined, opts: SshConnectOptions): Promise<string> {
  const ctx = conn.ctx;
  const gen = ++conn.gen;
  conn.endpoint = endpointOf(config);
  const finalConfig: ConnectConfig = {
    keepaliveInterval: DEFAULT_KEEPALIVE_MS,
    keepaliveCountMax: 3,
    readyTimeout: DEFAULT_READY_TIMEOUT_MS,
    ...config,
  };
  const expected = opts.expectedHostKey ? normalizeHostKeyFingerprint(opts.expectedHostKey) : undefined;
  let seenHostKey: string | undefined;
  let mismatch: string | undefined;
  /* Runs in every KEX (rekeys too) for direct and proxied sockets alike; without hostHash ssh2 passes the raw key blob. */
  finalConfig.hostVerifier = (key: Buffer) => {
    const fp = hostKeyFingerprint(key);
    const want = expected ?? seenHostKey;
    seenHostKey ??= fp;
    if (want && fp !== want) {
      mismatch = fp;
      return false;
    }
    return true;
  };
  delete finalConfig.hostHash;
  /* finalConfig keeps the name for display and reconnects; only the dial uses the checked address. */
  const dialConfig: ConnectConfig = { ...finalConfig };
  if (proxy) {
    const proxyAddress = await connectAddress(ctx, proxy.host, "Proxy");
    dialConfig.sock = await buildProxySocket(
      proxy,
      String(finalConfig.host),
      Number(finalConfig.port || 22),
      proxyAddress
    );
  } else {
    dialConfig.host = await connectAddress(ctx, String(finalConfig.host), "Host");
  }
  const label = `${finalConfig.host}:${finalConfig.port || 22}`;
  return new Promise((resolve, reject) => {
    const client = new Client();
    let settled = false;
    client.on("ready", () => {
      settled = true;
      if (gen !== conn.gen || ctx.destroyed || ctx.connections.get(conn.key) !== conn) {
        closeClient(client);
        reject(new Error(`Connection to ${label} was superseded by a newer connect/disconnect`));
        return;
      }
      const fromProfile = opts.profile !== undefined;
      if (fromProfile) {
        /* Best effort: ssh2 itself still holds the parsed key (and the last password auth) inside its closures. */
        for (const c of [config, finalConfig, dialConfig]) dropSecrets(c);
        const kept = (client as unknown as { config?: ConnectConfig }).config;
        if (kept) dropSecrets(kept);
      }
      /* A profile's proxy is re-resolved from the store on reconnect; only its route is kept. */
      const route = proxy && fromProfile ? withoutProxyPassword(proxy) : proxy;
      const pinned = !!expected && opts.pinned === true;
      conn.session = {
        client,
        config: finalConfig,
        connected: true,
        startTime: new Date(),
        proxyUsed: route,
        id: randomBytes(8).toString("hex"),
        target: `${finalConfig.username}@${label}${proxy ? ` via ${describeProxy(proxy)}` : ""}`,
        hostKeySha256: seenHostKey,
        hostKeyPinned: pinned,
      };
      const proxyStr = proxy ? ` via ${describeProxy(proxy)}` : "";
      conn.lastConnect = {
        config,
        profile: opts.profile,
        proxy: route,
        label,
        hostKeySha256: seenHostKey,
        hostKeyPinned: pinned,
      };
      addLog(conn, "info", `Connected to ${label}${proxyStr}`);
      resolve(`✅ Connected to ${label}${proxyStr}`);
    });
    client.on("error", (err) => {
      if (!settled) {
        settled = true;
        if (mismatch && expected) {
          const e = new HostKeyMismatchError(`${finalConfig.username}@${label}`, expected, mismatch, ctx.mode, opts.pinned === true);
          addLog(conn, "error", e.message);
          reject(e);
          return;
        }
        reject(new Error(`Connection error: ${err.message}`));
      } else {
        addLog(conn, "error", `Network error: ${err.message}`);
      }
    });
    client.on("close", () => {
      /* ssh2 closes without an 'error' when the peer hangs up after its banner. */
      if (!settled) {
        settled = true;
        reject(new Error(`Connection to ${label} closed before authentication completed`));
        return;
      }
      if (conn.session?.client === client) {
        addLog(conn, "info", "Connection closed");
        conn.session.connected = false;
        conn.session.sftp = undefined;
      }
    });
    client.connect(dialConfig);
  });
}


/* A profile connection keeps no credentials: they are re-read by name, and only while the profile still points at
 * the endpoint that was connected (a changed profile must be connected again on purpose). */
async function redial(conn: Conn, last: LastConnect): Promise<string> {
  let config = last.config;
  let expected = last.hostKeySha256;
  let pinned = last.hostKeyPinned === true;
  let proxy = last.proxy;
  if (last.profile !== undefined) {
    const cfg = conn.ctx.store.load();
    const fresh = getServerProfile(cfg, last.profile);
    if (!fresh) throw new Error(`Profile "${last.profile}" no longer exists; the dropped connection was not re-established`);
    if (endpointOf(fresh) !== endpointOf(last.config)) {
      throw new Error(
        `Profile "${last.profile}" now points at ${endpointOf(fresh)}, not ${endpointOf(last.config)} it was connected to; ` +
          `not reconnecting. ssh_disconnect {profile: "${conn.name}"}, then connect again.`
      );
    }
    proxy = resolveProxyForProfile(conn.ctx, fresh, cfg);
    if (proxyRoute(proxy) !== proxyRoute(last.proxy)) {
      throw new Error(
        `The proxy route of profile "${last.profile}" changed since it was connected (${describeProxy(last.proxy) || "direct"} → ` +
          `${describeProxy(proxy) || "direct"}); not reconnecting. ssh_disconnect {profile: "${conn.name}"}, then connect again.`
      );
    }
    config = profileToConnectConfig(conn.ctx.store, fresh);
    if (fresh.hostKeySha256) {
      expected = normalizeHostKeyFingerprint(fresh.hostKeySha256);
      pinned = true;
    }
  }
  return dial(conn, config, proxy, { expectedHostKey: expected, pinned, profile: last.profile });
}

/** Waits for a connect in flight, or reconnects with the last connect parameters when the session dropped
 * (keepalive miss, idle cut, network blip). Returns a note for the caller's result, or null. */
export async function ensureConnected(conn: Conn): Promise<string | null> {
  if (conn.session?.connected) return null;
  if (conn.connecting) {
    await conn.connecting;
    return null;
  }
  const last = conn.lastConnect;
  if (!last) return null;
  if (conn.session) {
    closeClient(conn.session.client);
    conn.session = null;
  }
  const attempt: Promise<string> = redial(conn, last)
    .then(() => `♻️ Session to ${conn.name} (${last.label}) had dropped; reconnected automatically.`)
    .finally(() => { if (conn.connecting === attempt) conn.connecting = null; });
  conn.connecting = attempt;
  return attempt;
}

/** Rejects when a connection-bound operation exceeds its deadline. The connection (resolved when the deadline
 * fires, so a call can find its connection inside the deadline) is marked dead so the next call reconnects, and a
 * handshake still in flight is voided. */
export function withDeadline<T>(target: Conn | (() => Conn | undefined) | undefined, promise: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      const conn = typeof target === "function" ? target() : target;
      if (conn) {
        addLog(conn, "error", `${label} timed out after ${ms} ms; connection marked dead`);
        if (conn.session) {
          conn.session.connected = false;
          closeClient(conn.session.client);
        }
        if (conn.connecting) {
          conn.gen++;
          conn.connecting = null;
          /* A first connect voided here leaves nothing to reconnect to. */
          if (!conn.session && !conn.lastConnect) closeConn(conn);
        }
      }
      reject(new Error(`${label} timed out after ${Math.round(ms / 1000)} s; ${conn ? `the connection to ${conn.name} was reset, ` : ""}retry the call`));
    }, ms);
    promise.then(
      (value) => { clearTimeout(timer); resolve(value); },
      (err) => { clearTimeout(timer); reject(err); }
    );
  });
}

/** Returns the connection's shared SFTP channel, opening it on first use. */
export function getSftp(conn: Conn): Promise<SFTPWrapper> {
  const session = conn.session;
  if (!session?.connected) return Promise.reject(new Error(`No active SSH connection to ${conn.name}`));
  if (session.sftp) return session.sftp;
  const forget = () => { if (session.sftp === opening) session.sftp = undefined; };
  const opening = new Promise<SFTPWrapper>((resolve, reject) => {
    session.client.sftp((err, sftp) => {
      if (err) {
        addLog(conn, "error", `SFTP: ${err.message}`);
        return reject(err);
      }
      /* Without an 'error' listener a protocol error on this long-lived channel would crash the process. */
      sftp.on("error", (e: Error) => { addLog(conn, "error", `SFTP channel: ${e.message}`); forget(); });
      sftp.on("end", forget);
      sftp.on("close", forget);
      resolve(sftp);
    });
  });
  session.sftp = opening;
  opening.catch(forget);
  return opening;
}

/** Closes one connection. cleanupTemp removes the temp files downloaded through it. */
export function sshDisconnect(conn: Conn, cleanupTemp = false): string {
  const ctx = conn.ctx;
  const session = conn.session;
  closeConn(conn);
  addLog(conn, "info", "Disconnected");
  const duration = session ? Math.round((Date.now() - session.startTime.getTime()) / 1000) : 0;
  let result = session
    ? `✅ Disconnected from ${conn.name} (${session.config.host}). Session: ${duration}s.`
    : `✅ Closed ${conn.name} (it was not connected).`;
  if (cleanupTemp) {
    let count = 0;
    for (const tf of listTempFiles(ctx)) {
      if (tf.connectionKey === conn.key && deleteTempFile(ctx, tf.id)) count++;
    }
    if (count > 0) result += `\n🗑️ Temp files removed: ${count}`;
  }
  const tempCount = listTempFiles(ctx).length;
  if (tempCount > 0) result += `\n📁 Temp files left: ${tempCount} (use ssh_temp_cleanup to clear)`;
  return result;
}

/** Dials host:port (through the proxy if given), lets key exchange run, records the host key and refuses it, so
 * authentication never starts and no credential is involved. Returns "SHA256:<base64>". */
export async function scanHostKey(host: string, port: number, proxy?: ProxyConfig | null, timeoutMs = DEFAULT_READY_TIMEOUT_MS): Promise<string> {
  const sock = proxy ? await buildProxySocket(proxy, host, port) : undefined;
  return new Promise((resolve, reject) => {
    const client = new Client();
    let seen: string | undefined;
    let done = false;
    const finish = (err?: Error) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      closeClient(client);
      if (seen) resolve(seen);
      else reject(err ?? new Error(`${host}:${port} closed the connection before presenting a host key`));
    };
    const timer = setTimeout(() => finish(new Error(`${host}:${port} presented no host key within ${Math.round(timeoutMs / 1000)} s`)), timeoutMs);
    client.on("error", (e) => finish(seen ? undefined : new Error(`${host}:${port}: ${e.message}`)));
    client.on("close", () => finish());
    client.on("ready", () => finish(new Error("unexpected authentication success")));
    try {
      client.connect({
        host,
        port,
        sock,
        username: "mcp-sshpilot-scan",
        readyTimeout: timeoutMs,
        hostVerifier: (key: Buffer) => {
          seen = hostKeyFingerprint(key);
          return false;
        },
      });
    } catch (e) {
      finish(e as Error);
    }
  });
}

export interface CommandResult {
  stdout: string;
  stderr: string;
  code: number | null;
  signal?: string;
  timedOut: boolean;
  limitMs: number;
}

/* A command that forks a process inheriting stdout keeps the channel open forever,
 * so every exec has a hard timeout that kills the channel and returns partial output.
 * Output is kept as a bounded tail so `cat hugefile` cannot exhaust memory. */
export function runCommand(conn: Conn, command: string, timeoutMs?: number, stdin?: string): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    if (!conn.session?.connected) {
      reject(new Error(`No active SSH connection to ${conn.name}`));
      return;
    }
    const limitMs = clampTimeout(timeoutMs) ?? DEFAULT_EXEC_TIMEOUT_MS;
    /* A script fed through stdin can carry secrets: the log gets its size only. */
    addLog(conn, "command", stdin === undefined ? command : `${command} [stdin: ${Buffer.byteLength(stdin)} bytes]`);

    conn.session.client.exec(command, (err, stream) => {
      if (err) {
        addLog(conn, "error", err.message);
        reject(err);
        return;
      }
      const stdout = new OutputTail(EXEC_OUTPUT_CAP);
      const stderr = new OutputTail(EXEC_OUTPUT_CAP);
      let finished = false;
      const finish = (code: number | null, signal: string | undefined, timedOut: boolean) => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        stdout.finish();
        stderr.finish();
        resolve({ stdout: stdout.toString(), stderr: stderr.toString(), code, signal, timedOut, limitMs });
      };

      const timer = setTimeout(() => {
        addLog(conn, "warning", `Command timeout (${limitMs}ms): ${command}`);
        try { if (typeof (stream as any).signal === "function") (stream as any).signal("KILL"); } catch { /* ignore */ }
        try { stream.close(); } catch { /* ignore */ }
        finish(null, undefined, true);
      }, limitMs);

      stream.on("close", (code: number | null, signal?: string) => finish(code ?? null, signal, false));
      stream.on("data", (data: Buffer) => stdout.push(data));
      stream.stderr.on("data", (data: Buffer) => stderr.push(data));
      if (stdin !== undefined) stream.end(stdin);
    });
  });
}

/** Remote mode: a running call keeps its session from the idle sweep and from eviction, so it may not run for weeks. */
export const REMOTE_MAX_EXEC_TIMEOUT_MS = 60 * 60 * 1000;

/* setTimeout fires immediately for delays above 2^31-1 ms. */
export function clampTimeout(ms: unknown, max: number = 2_000_000_000): number | undefined {
  return typeof ms === "number" && ms > 0 ? Math.min(ms, max) : undefined;
}

/* Runs a POSIX sh script fed through stdin, so the login shell (fish, PowerShell, ...) never parses our quoting. */
export function runScript(conn: Conn, script: string, timeoutMs?: number): Promise<CommandResult> {
  return runCommand(conn, "sh -s", timeoutMs, script);
}

export async function sshExecute(conn: Conn, command: string, timeoutMs?: number): Promise<string> {
  const r = await runCommand(conn, command, timeoutMs);
  if (r.timedOut) {
    return (
      `⚠️ Command did not finish within ${r.limitMs}ms — channel closed.\n` +
      `Hint: use ssh_execute_background for long-running commands.\n` +
      `If the command forks a daemon, redirect descriptors: \`cmd > /dev/null 2>&1 < /dev/null & disown\`.\n\n` +
      `--- partial stdout ---\n${r.stdout || "(empty)"}\n` +
      `--- partial stderr ---\n${r.stderr || "(empty)"}`
    );
  }
  let output = r.stdout + (r.stderr ? `\n[STDERR]: ${r.stderr}` : "");
  addLog(conn, "output", output || "(empty output)");
  if (r.code !== 0) {
    const status = r.code === null ? `none${r.signal ? `, signal ${r.signal}` : ""}` : String(r.code);
    addLog(conn, "warning", `Command exited with code ${status}`);
    output = `${output || "(no output)"}\n[exit code: ${status}]`;
  }
  return output || "(command finished with no output)";
}

export async function sshExecuteBackground(conn: Conn, command: string): Promise<{ id: string }> {
  const ctx = conn.ctx;
  return new Promise((resolve, reject) => {
    if (!conn.session?.connected) {
      reject(new Error(`No active SSH connection to ${conn.name}`));
      return;
    }
    if (ctx.mode === "remote" && ctx.backgroundJobs.size >= REMOTE_MAX_BACKGROUND_JOBS && !dropOldestFinishedJob(ctx)) {
      reject(new Error(`${REMOTE_MAX_BACKGROUND_JOBS} background jobs are still running in this session; stop some with ssh_kill_background first`));
      return;
    }
    addLog(conn, "command", `[bg] ${command}`);
    conn.session.client.exec(command, (err, stream) => {
      if (err) {
        addLog(conn, "error", err.message);
        reject(err);
        return;
      }
      const id = generateId();
      const job: BackgroundJob = {
        id,
        conn: conn.name,
        connKey: conn.key,
        command: command.length > JOB_COMMAND_DISPLAY_CHARS ? detach(command.slice(0, JOB_COMMAND_DISPLAY_CHARS)) + "...[trimmed]" : command,
        startedAt: new Date(),
        stdout: new OutputTail(BACKGROUND_OUTPUT_CAP),
        stderr: new OutputTail(BACKGROUND_OUTPUT_CAP),
        done: false,
        exitCode: null,
        stream,
      };
      /* Parallel starts can all pass the check above; trim back here as far as finished jobs allow. stdio trims too:
       * a long session would otherwise keep every finished job's output tails forever. */
      while (ctx.backgroundJobs.size >= REMOTE_MAX_BACKGROUND_JOBS && dropOldestFinishedJob(ctx)) ;
      ctx.backgroundJobs.set(id, job);

      stream.on("close", (code: number) => {
        job.stdout.finish();
        job.stderr.finish();
        job.done = true;
        job.exitCode = code;
        addLog(conn, "info", `[bg ${id}] finished code=${code}`);
      });
      stream.on("data", (data: Buffer) => job.stdout.push(data));
      stream.stderr.on("data", (data: Buffer) => job.stderr.push(data));

      resolve({ id });
    });
  });
}

/* Map order is insertion order, so the first finished job found is the oldest one. */
function dropOldestFinishedJob(ctx: SessionCtx): boolean {
  for (const [id, job] of ctx.backgroundJobs) {
    if (job.done) {
      ctx.backgroundJobs.delete(id);
      return true;
    }
  }
  return false;
}

export function readBackgroundJob(ctx: SessionCtx, id: string, tail?: number): string {
  const job = ctx.backgroundJobs.get(id);
  if (!job) return `❌ Job ${id} not found (finished jobs beyond the newest ${REMOTE_MAX_BACKGROUND_JOBS} are dropped)`;
  const sliceTail = (s: string, n?: number) =>
    !n || s.length <= n ? s : "...[truncated]..." + s.slice(-n);
  const stdout = sliceTail(job.stdout.toString(), tail);
  const stderr = sliceTail(job.stderr.toString(), tail);
  const status = job.done ? `done (code=${job.exitCode})` : "running";
  const elapsed = Math.round((Date.now() - job.startedAt.getTime()) / 1000);
  return (
    `Job ${id} [${status}] elapsed=${elapsed}s\n` +
    `Connection: ${job.conn}\n` +
    `Command: ${job.command}\n` +
    `--- stdout (${job.stdout.total}b) ---\n${stdout || "(empty)"}\n` +
    `--- stderr (${job.stderr.total}b) ---\n${stderr || "(empty)"}`
  );
}

export async function killBackgroundJob(ctx: SessionCtx, id: string): Promise<string> {
  const job = ctx.backgroundJobs.get(id);
  if (!job) return `❌ Job ${id} not found`;
  if (job.done) return `Job ${id} already finished (code=${job.exitCode})`;
  try {
    if (job.stream && typeof job.stream.signal === "function") job.stream.signal("KILL");
    if (job.stream && typeof job.stream.close === "function") job.stream.close();
    if (job.stream && typeof job.stream.end === "function") job.stream.end();
  } catch (e: any) {
    addLog(ctx, "error", `kill ${id}: ${e.message}`);
  }
  await new Promise((r) => setTimeout(r, 200));
  return `Signal sent to job ${id}. Done=${job.done} exitCode=${job.exitCode}`;
}

/** filter: only the jobs of that connection (name, case-insensitive). */
export function listBackgroundJobs(ctx: SessionCtx, filter?: string): string {
  const keys = filter === undefined ? undefined : keysOfName(filter);
  const jobs = Array.from(ctx.backgroundJobs.values()).filter((j) => keys === undefined || keys.includes(j.connKey));
  if (jobs.length === 0) return filter === undefined ? "No background jobs" : `No background jobs on ${filter}`;
  return jobs
    .map((j) => {
      const elapsed = Math.round((Date.now() - j.startedAt.getTime()) / 1000);
      const status = j.done ? `done(${j.exitCode})` : "running";
      const cmd = j.command.length > 80 ? j.command.slice(0, 77) + "..." : j.command;
      return `${j.id} [${status}] ${elapsed}s ${j.conn} | ${cmd}`;
    })
    .join("\n");
}
