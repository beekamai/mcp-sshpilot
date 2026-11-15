import { Client, ConnectConfig, SFTPWrapper } from "ssh2";
import type { ProxyConfig, BackgroundJob } from "./types.js";
import {
  addLog,
  closeClient,
  DEFAULT_EXEC_TIMEOUT_MS,
  DEFAULT_KEEPALIVE_MS,
  DEFAULT_READY_TIMEOUT_MS,
} from "./state.js";
import type { SessionCtx, SessionMode } from "./state.js";
import { createHash, randomBytes } from "crypto";
import { lookup } from "dns/promises";
import { BlockList, isIP } from "net";
import { buildProxySocket, describeProxy } from "./proxy.js";
import { detach, generateId, OutputTail } from "./utils.js";
import { listTempFiles, cleanupAllTempFiles } from "./temp.js";

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
  /** pinned: expected is a profile's pin; otherwise only the key an earlier connect of this session saw. */
  constructor(
    readonly target: string,
    readonly expected: string,
    readonly actual: string,
    mode: SessionMode,
    pinned = true
  ) {
    super(
      `HOST KEY MISMATCH for ${target}: ${pinned ? "pinned" : "earlier in this session the server presented"} ${expected}, server presented ${actual}. ` +
        `Connection refused before authentication; no credentials were sent and nothing was executed. ` +
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
}

export async function sshConnect(
  ctx: SessionCtx,
  config: ConnectConfig,
  proxy?: ProxyConfig,
  opts: SshConnectOptions = {}
): Promise<string> {
  if (ctx.destroyed) throw new Error("Session is closed");
  if (ctx.session?.connected) {
    throw new Error("There is already an active connection. Disconnect first.");
  }
  const gen = ++ctx.connectGen;
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
  const dial: ConnectConfig = { ...finalConfig };
  if (proxy) {
    const proxyAddress = await connectAddress(ctx, proxy.host, "Proxy");
    dial.sock = await buildProxySocket(
      proxy,
      String(finalConfig.host),
      Number(finalConfig.port || 22),
      proxyAddress
    );
  } else {
    dial.host = await connectAddress(ctx, String(finalConfig.host), "Host");
  }
  const label = `${finalConfig.host}:${finalConfig.port || 22}`;
  return new Promise((resolve, reject) => {
    const client = new Client();
    let settled = false;
    client.on("ready", () => {
      settled = true;
      if (gen !== ctx.connectGen) {
        closeClient(client);
        reject(new Error(`Connection to ${label} was superseded by a newer connect/disconnect`));
        return;
      }
      ctx.session = {
        client,
        config: finalConfig,
        connected: true,
        logs: [],
        startTime: new Date(),
        proxyUsed: proxy,
        id: randomBytes(8).toString("hex"),
        target: `${finalConfig.username}@${label}${proxy ? ` via ${describeProxy(proxy)}` : ""}`,
        hostKeySha256: seenHostKey,
        hostKeyPinned: !!expected && opts.pinned === true,
      };
      const proxyStr = proxy ? ` via ${describeProxy(proxy)}` : "";
      ctx.lastConnect = { config, proxy, label, hostKeySha256: seenHostKey, hostKeyPinned: !!expected && opts.pinned === true };
      addLog(ctx, "info", `Connected to ${label}${proxyStr}`);
      resolve(`✅ Connected to ${label}${proxyStr}`);
    });
    client.on("error", (err) => {
      if (!settled) {
        settled = true;
        if (mismatch && expected) {
          const e = new HostKeyMismatchError(`${finalConfig.username}@${label}`, expected, mismatch, ctx.mode, opts.pinned === true);
          addLog(ctx, "error", e.message);
          reject(e);
          return;
        }
        reject(new Error(`Connection error: ${err.message}`));
      } else {
        addLog(ctx, "error", `Network error: ${err.message}`);
      }
    });
    client.on("close", () => {
      if (ctx.session?.client === client) {
        addLog(ctx, "info", "Connection closed");
        ctx.session.connected = false;
        ctx.session.sftp = undefined;
      }
    });
    client.connect(dial);
  });
}

/** Reconnects with the last connect parameters when the session dropped (keepalive miss, idle cut, network blip). */
export async function ensureConnected(ctx: SessionCtx): Promise<string | null> {
  if (ctx.session?.connected) return null;
  const last = ctx.lastConnect;
  if (!last) return null;
  if (!ctx.reconnecting) {
    if (ctx.session) {
      closeClient(ctx.session.client);
      ctx.session = null;
    }
    const attempt: Promise<string> = sshConnect(ctx, last.config, last.proxy, { expectedHostKey: last.hostKeySha256, pinned: last.hostKeyPinned })
      .then(() => `♻️ Session to ${last.label} had dropped; reconnected automatically.`)
      .finally(() => { if (ctx.reconnecting === attempt) ctx.reconnecting = null; });
    ctx.reconnecting = attempt;
  }
  return ctx.reconnecting;
}

/** Rejects when a session-bound operation exceeds its deadline and marks the session dead so the next call reconnects. */
export function withDeadline<T>(ctx: SessionCtx, promise: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      addLog(ctx, "error", `${label} timed out after ${ms} ms; session marked dead`);
      if (ctx.session) {
        ctx.session.connected = false;
        closeClient(ctx.session.client);
      }
      reject(new Error(`${label} timed out after ${Math.round(ms / 1000)} s; the session was reset, retry the call`));
    }, ms);
    promise.then(
      (value) => { clearTimeout(timer); resolve(value); },
      (err) => { clearTimeout(timer); reject(err); }
    );
  });
}

/** Returns the session's shared SFTP channel, opening it on first use. */
export function getSftp(ctx: SessionCtx): Promise<SFTPWrapper> {
  const session = ctx.session;
  if (!session?.connected) return Promise.reject(new Error("No active SSH connection"));
  if (session.sftp) return session.sftp;
  const forget = () => { if (session.sftp === opening) session.sftp = undefined; };
  const opening = new Promise<SFTPWrapper>((resolve, reject) => {
    session.client.sftp((err, sftp) => {
      if (err) {
        addLog(ctx, "error", `SFTP: ${err.message}`);
        return reject(err);
      }
      /* Without an 'error' listener a protocol error on this long-lived channel would crash the process. */
      sftp.on("error", (e: Error) => { addLog(ctx, "error", `SFTP channel: ${e.message}`); forget(); });
      sftp.on("end", forget);
      sftp.on("close", forget);
      resolve(sftp);
    });
  });
  session.sftp = opening;
  opening.catch(forget);
  return opening;
}

export function sshDisconnect(ctx: SessionCtx, cleanupTemp = false): string {
  ctx.connectGen++;
  ctx.lastConnect = null;
  if (!ctx.session) return "No active connection";
  closeClient(ctx.session.client);
  const host = ctx.session.config.host;
  const duration = Math.round((Date.now() - ctx.session.startTime.getTime()) / 1000);
  ctx.session = null;
  let result = `✅ Disconnected from ${host}. Session: ${duration}s.`;
  if (cleanupTemp) {
    const count = cleanupAllTempFiles(ctx);
    if (count > 0) result += `\n🗑️ Temp files removed: ${count}`;
  } else {
    const tempCount = listTempFiles(ctx).length;
    if (tempCount > 0) result += `\n📁 Temp files left: ${tempCount} (use ssh_temp_cleanup to clear)`;
  }
  return result;
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
export function runCommand(ctx: SessionCtx, command: string, timeoutMs?: number, stdin?: string): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    if (!ctx.session?.connected) {
      reject(new Error("No active SSH connection"));
      return;
    }
    const limitMs = clampTimeout(timeoutMs) ?? DEFAULT_EXEC_TIMEOUT_MS;
    addLog(ctx, "command", stdin === undefined ? command : `${command} <<< ${stdin}`);

    ctx.session.client.exec(command, (err, stream) => {
      if (err) {
        addLog(ctx, "error", err.message);
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
        addLog(ctx, "warning", `Command timeout (${limitMs}ms): ${command}`);
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
export function runScript(ctx: SessionCtx, script: string, timeoutMs?: number): Promise<CommandResult> {
  return runCommand(ctx, "sh -s", timeoutMs, script);
}

export async function sshExecute(ctx: SessionCtx, command: string, timeoutMs?: number): Promise<string> {
  const r = await runCommand(ctx, command, timeoutMs);
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
  addLog(ctx, "output", output || "(empty output)");
  if (r.code !== 0) {
    const status = r.code === null ? `none${r.signal ? `, signal ${r.signal}` : ""}` : String(r.code);
    addLog(ctx, "warning", `Command exited with code ${status}`);
    output = `${output || "(no output)"}\n[exit code: ${status}]`;
  }
  return output || "(command finished with no output)";
}

export async function sshExecuteBackground(ctx: SessionCtx, command: string): Promise<{ id: string }> {
  return new Promise((resolve, reject) => {
    if (!ctx.session?.connected) {
      reject(new Error("No active SSH connection"));
      return;
    }
    if (ctx.mode === "remote" && ctx.backgroundJobs.size >= REMOTE_MAX_BACKGROUND_JOBS && !dropOldestFinishedJob(ctx)) {
      reject(new Error(`${REMOTE_MAX_BACKGROUND_JOBS} background jobs are still running in this session; stop some with ssh_kill_background first`));
      return;
    }
    addLog(ctx, "command", `[bg] ${command}`);
    ctx.session.client.exec(command, (err, stream) => {
      if (err) {
        addLog(ctx, "error", err.message);
        reject(err);
        return;
      }
      const id = generateId();
      const job: BackgroundJob = {
        id,
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
        addLog(ctx, "info", `[bg ${id}] finished code=${code}`);
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

export function listBackgroundJobs(ctx: SessionCtx): string {
  if (ctx.backgroundJobs.size === 0) return "No background jobs";
  return Array.from(ctx.backgroundJobs.values())
    .map((j) => {
      const elapsed = Math.round((Date.now() - j.startedAt.getTime()) / 1000);
      const status = j.done ? `done(${j.exitCode})` : "running";
      const cmd = j.command.length > 80 ? j.command.slice(0, 77) + "..." : j.command;
      return `${j.id} [${status}] ${elapsed}s | ${cmd}`;
    })
    .join("\n");
}
