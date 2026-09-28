import { Client, ConnectConfig, SFTPWrapper } from "ssh2";
import type { ProxyConfig, BackgroundJob } from "./types.js";
import {
  state,
  addLog,
  backgroundJobs,
  DEFAULT_EXEC_TIMEOUT_MS,
  DEFAULT_KEEPALIVE_MS,
  DEFAULT_READY_TIMEOUT_MS,
} from "./state.js";
import { randomBytes } from "crypto";
import { buildProxySocket, describeProxy } from "./proxy.js";
import { generateId, OutputTail } from "./utils.js";
import { listTempFiles, cleanupAllTempFiles } from "./temp.js";

const EXEC_OUTPUT_CAP = 1024 * 1024;
const BACKGROUND_OUTPUT_CAP = 256 * 1024;

/* Bumped by every connect/disconnect: a slow handshake (e.g. an auto-reconnect) that finishes after
 * the user disconnected or connected elsewhere must not overwrite the newer session. */
let connectGen = 0;

export async function sshConnect(
  config: ConnectConfig,
  proxy?: ProxyConfig
): Promise<string> {
  if (state.session?.connected) {
    throw new Error("There is already an active connection. Disconnect first.");
  }
  const gen = ++connectGen;
  const finalConfig: ConnectConfig = {
    keepaliveInterval: DEFAULT_KEEPALIVE_MS,
    keepaliveCountMax: 3,
    readyTimeout: DEFAULT_READY_TIMEOUT_MS,
    ...config,
  };
  if (proxy) {
    const sock = await buildProxySocket(
      proxy,
      String(finalConfig.host),
      Number(finalConfig.port || 22)
    );
    (finalConfig as any).sock = sock;
  }
  const label = `${finalConfig.host}:${finalConfig.port || 22}`;
  return new Promise((resolve, reject) => {
    const client = new Client();
    let settled = false;
    client.on("ready", () => {
      settled = true;
      if (gen !== connectGen) {
        client.end();
        reject(new Error(`Connection to ${label} was superseded by a newer connect/disconnect`));
        return;
      }
      state.session = {
        client,
        config: finalConfig,
        connected: true,
        logs: [],
        startTime: new Date(),
        proxyUsed: proxy,
        id: randomBytes(8).toString("hex"),
        target: `${finalConfig.username}@${label}${proxy ? ` via ${describeProxy(proxy)}` : ""}`,
      };
      const proxyStr = proxy ? ` via ${describeProxy(proxy)}` : "";
      state.lastConnect = { config, proxy, label };
      addLog("info", `Connected to ${label}${proxyStr}`);
      resolve(`✅ Connected to ${label}${proxyStr}`);
    });
    client.on("error", (err) => {
      if (!settled) {
        settled = true;
        reject(new Error(`Connection error: ${err.message}`));
      } else {
        addLog("error", `Network error: ${err.message}`);
      }
    });
    client.on("close", () => {
      if (state.session?.client === client) {
        addLog("info", "Connection closed");
        state.session.connected = false;
        state.session.sftp = undefined;
      }
    });
    client.connect(finalConfig);
  });
}

let reconnecting: Promise<string> | null = null;

/** Reconnects with the last connect parameters when the session dropped (keepalive miss, idle cut, network blip). */
export async function ensureConnected(): Promise<string | null> {
  if (state.session?.connected) return null;
  const last = state.lastConnect;
  if (!last) return null;
  /* Parallel tool calls share one reconnect; otherwise each opens a Client and all but the last leak. */
  if (!reconnecting) {
    if (state.session) {
      try { state.session.client.end(); } catch { /* already gone */ }
      state.session = null;
    }
    reconnecting = sshConnect(last.config, last.proxy)
      .then(() => `♻️ Session to ${last.label} had dropped; reconnected automatically.`)
      .finally(() => { reconnecting = null; });
  }
  return reconnecting;
}

/** Rejects when a session-bound operation exceeds its deadline and marks the session dead so the next call reconnects. */
export function withDeadline<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      addLog("error", `${label} timed out after ${ms} ms; session marked dead`);
      if (state.session) {
        state.session.connected = false;
        try { state.session.client.end(); } catch { /* already gone */ }
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
export function getSftp(): Promise<SFTPWrapper> {
  const session = state.session;
  if (!session?.connected) return Promise.reject(new Error("No active SSH connection"));
  if (session.sftp) return session.sftp;
  const forget = () => { if (session.sftp === opening) session.sftp = undefined; };
  const opening = new Promise<SFTPWrapper>((resolve, reject) => {
    session.client.sftp((err, sftp) => {
      if (err) {
        addLog("error", `SFTP: ${err.message}`);
        return reject(err);
      }
      /* Without an 'error' listener a protocol error on this long-lived channel would crash the process. */
      sftp.on("error", (e: Error) => { addLog("error", `SFTP channel: ${e.message}`); forget(); });
      sftp.on("end", forget);
      sftp.on("close", forget);
      resolve(sftp);
    });
  });
  session.sftp = opening;
  opening.catch(forget);
  return opening;
}

export function sshDisconnect(cleanupTemp = false): string {
  connectGen++;
  state.lastConnect = null;
  if (!state.session) return "No active connection";
  state.session.client.end();
  const host = state.session.config.host;
  const duration = Math.round((Date.now() - state.session.startTime.getTime()) / 1000);
  state.session = null;
  let result = `✅ Disconnected from ${host}. Session: ${duration}s.`;
  if (cleanupTemp) {
    const count = cleanupAllTempFiles();
    if (count > 0) result += `\n🗑️ Temp files removed: ${count}`;
  } else {
    const tempCount = listTempFiles().length;
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
export function runCommand(command: string, timeoutMs?: number, stdin?: string): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    if (!state.session?.connected) {
      reject(new Error("No active SSH connection"));
      return;
    }
    const limitMs = clampTimeout(timeoutMs) ?? DEFAULT_EXEC_TIMEOUT_MS;
    addLog("command", stdin === undefined ? command : `${command} <<< ${stdin}`);

    state.session.client.exec(command, (err, stream) => {
      if (err) {
        addLog("error", err.message);
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
        addLog("warning", `Command timeout (${limitMs}ms): ${command}`);
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

/* setTimeout fires immediately for delays above 2^31-1 ms. */
export function clampTimeout(ms: unknown): number | undefined {
  return typeof ms === "number" && ms > 0 ? Math.min(ms, 2_000_000_000) : undefined;
}

/* Runs a POSIX sh script fed through stdin, so the login shell (fish, PowerShell, ...) never parses our quoting. */
export function runScript(script: string, timeoutMs?: number): Promise<CommandResult> {
  return runCommand("sh -s", timeoutMs, script);
}

export async function sshExecute(command: string, timeoutMs?: number): Promise<string> {
  const r = await runCommand(command, timeoutMs);
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
  addLog("output", output || "(empty output)");
  if (r.code !== 0) {
    const status = r.code === null ? `none${r.signal ? `, signal ${r.signal}` : ""}` : String(r.code);
    addLog("warning", `Command exited with code ${status}`);
    output = `${output || "(no output)"}\n[exit code: ${status}]`;
  }
  return output || "(command finished with no output)";
}

export async function sshExecuteBackground(command: string): Promise<{ id: string }> {
  return new Promise((resolve, reject) => {
    if (!state.session?.connected) {
      reject(new Error("No active SSH connection"));
      return;
    }
    addLog("command", `[bg] ${command}`);
    state.session.client.exec(command, (err, stream) => {
      if (err) {
        addLog("error", err.message);
        reject(err);
        return;
      }
      const id = generateId();
      const job: BackgroundJob = {
        id,
        command,
        startedAt: new Date(),
        stdout: new OutputTail(BACKGROUND_OUTPUT_CAP),
        stderr: new OutputTail(BACKGROUND_OUTPUT_CAP),
        done: false,
        exitCode: null,
        stream,
      };
      backgroundJobs.set(id, job);

      stream.on("close", (code: number) => {
        job.stdout.finish();
        job.stderr.finish();
        job.done = true;
        job.exitCode = code;
        addLog("info", `[bg ${id}] finished code=${code}`);
      });
      stream.on("data", (data: Buffer) => job.stdout.push(data));
      stream.stderr.on("data", (data: Buffer) => job.stderr.push(data));

      resolve({ id });
    });
  });
}

export function readBackgroundJob(id: string, tail?: number): string {
  const job = backgroundJobs.get(id);
  if (!job) return `❌ Job ${id} not found`;
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

export async function killBackgroundJob(id: string): Promise<string> {
  const job = backgroundJobs.get(id);
  if (!job) return `❌ Job ${id} not found`;
  if (job.done) return `Job ${id} already finished (code=${job.exitCode})`;
  try {
    if (job.stream && typeof job.stream.signal === "function") job.stream.signal("KILL");
    if (job.stream && typeof job.stream.close === "function") job.stream.close();
    if (job.stream && typeof job.stream.end === "function") job.stream.end();
  } catch (e: any) {
    addLog("error", `kill ${id}: ${e.message}`);
  }
  await new Promise((r) => setTimeout(r, 200));
  return `Signal sent to job ${id}. Done=${job.done} exitCode=${job.exitCode}`;
}

export function listBackgroundJobs(): string {
  if (backgroundJobs.size === 0) return "No background jobs";
  return Array.from(backgroundJobs.values())
    .map((j) => {
      const elapsed = Math.round((Date.now() - j.startedAt.getTime()) / 1000);
      const status = j.done ? `done(${j.exitCode})` : "running";
      const cmd = j.command.length > 80 ? j.command.slice(0, 77) + "..." : j.command;
      return `${j.id} [${status}] ${elapsed}s | ${cmd}`;
    })
    .join("\n");
}
