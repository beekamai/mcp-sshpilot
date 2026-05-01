import { Client, ConnectConfig } from "ssh2";
import type { ProxyConfig, BackgroundJob } from "./types.js";
import {
  state,
  addLog,
  backgroundJobs,
  DEFAULT_EXEC_TIMEOUT_MS,
  DEFAULT_KEEPALIVE_MS,
  DEFAULT_READY_TIMEOUT_MS,
} from "./state.js";
import { buildProxySocket, describeProxy } from "./proxy.js";
import { generateId } from "./utils.js";
import { listTempFiles, cleanupAllTempFiles } from "./temp.js";

export async function sshConnect(
  config: ConnectConfig,
  proxy?: ProxyConfig
): Promise<string> {
  if (state.session?.connected) {
    throw new Error("There is already an active connection. Disconnect first.");
  }
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
  return new Promise((resolve, reject) => {
    const client = new Client();
    let settled = false;
    client.on("ready", () => {
      settled = true;
      state.session = {
        client,
        config: finalConfig,
        connected: true,
        logs: [],
        startTime: new Date(),
        proxyUsed: proxy,
      };
      const proxyStr = proxy ? ` via ${describeProxy(proxy)}` : "";
      addLog("info", `Connected to ${finalConfig.host}:${finalConfig.port || 22}${proxyStr}`);
      resolve(`✅ Connected to ${finalConfig.host}:${finalConfig.port || 22}${proxyStr}`);
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
      if (state.session) {
        addLog("info", "Connection closed");
        state.session.connected = false;
      }
    });
    client.connect(finalConfig);
  });
}

export function sshDisconnect(cleanupTemp = false): string {
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

/* ssh_execute used to hang for several reasons:
 *   1. No keepaliveInterval — TCP drops weren't detected.
 *   2. No exec timeout — if the command forks a background process inheriting
 *      stdout/stderr, the channel's 'close' event never fires while that
 *      process lives (classic: `cmd &` without redirecting fds).
 *   3. Unbounded stdout/stderr buffers.
 * Fixes: keepalive in sshConnect, optional timeout that kills the channel,
 * and a buffer cap. For long-running/daemon commands use ssh_execute_background.
 */
export async function sshExecute(command: string, timeoutMs?: number): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!state.session?.connected) {
      reject(new Error("No active SSH connection"));
      return;
    }
    const limit =
      typeof timeoutMs === "number" && timeoutMs > 0 ? timeoutMs : DEFAULT_EXEC_TIMEOUT_MS;
    addLog("command", command);

    state.session.client.exec(command, (err, stream) => {
      if (err) {
        addLog("error", err.message);
        reject(err);
        return;
      }
      let stdout = "";
      let stderr = "";
      let timedOut = false;
      let finished = false;
      const cap = 1024 * 1024;
      const trim = (s: string) => (s.length > cap ? "...[trimmed]..." + s.slice(-cap) : s);

      const timer = setTimeout(() => {
        if (finished) return;
        timedOut = true;
        addLog("warning", `Command timeout (${limit}ms): ${command}`);
        try { if (typeof (stream as any).signal === "function") (stream as any).signal("KILL"); } catch { /* ignore */ }
        try { stream.close(); } catch { /* ignore */ }
        try { stream.end(); } catch { /* ignore */ }
        finished = true;
        resolve(
          `⚠️ Command did not finish within ${limit}ms — channel closed.\n` +
            `Hint: use ssh_execute_background for long-running commands.\n` +
            `If the command forks a daemon, redirect descriptors: \`cmd > /dev/null 2>&1 < /dev/null & disown\`.\n\n` +
            `--- partial stdout (${stdout.length}b) ---\n${trim(stdout) || "(empty)"}\n` +
            `--- partial stderr (${stderr.length}b) ---\n${trim(stderr) || "(empty)"}`
        );
      }, limit);

      stream.on("close", (code: number) => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        if (timedOut) return;
        const output = trim(stdout) + (stderr ? `\n[STDERR]: ${trim(stderr)}` : "");
        addLog("output", output || "(empty output)");
        if (code !== 0) addLog("warning", `Command exited with code ${code}`);
        resolve(output || "(command finished with no output)");
      });
      stream.on("data", (data: Buffer) => { stdout += data.toString(); });
      stream.stderr.on("data", (data: Buffer) => { stderr += data.toString(); });
    });
  });
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
        stdout: "",
        stderr: "",
        done: false,
        exitCode: null,
        stream,
      };
      backgroundJobs.set(id, job);

      stream.on("close", (code: number) => {
        job.done = true;
        job.exitCode = code;
        addLog("info", `[bg ${id}] finished code=${code}`);
      });
      stream.on("data", (data: Buffer) => { job.stdout += data.toString(); });
      stream.stderr.on("data", (data: Buffer) => { job.stderr += data.toString(); });

      const cap = 256 * 1024;
      const trimI = setInterval(() => {
        if (job.stdout.length > cap) job.stdout = "...[trimmed]..." + job.stdout.slice(-cap);
        if (job.stderr.length > cap) job.stderr = "...[trimmed]..." + job.stderr.slice(-cap);
      }, 5000);
      stream.on("close", () => clearInterval(trimI));

      resolve({ id });
    });
  });
}

export function readBackgroundJob(id: string, tail?: number): string {
  const job = backgroundJobs.get(id);
  if (!job) return `❌ Job ${id} not found`;
  const sliceTail = (s: string, n?: number) =>
    !n || s.length <= n ? s : "...[truncated]..." + s.slice(-n);
  const stdout = sliceTail(job.stdout, tail);
  const stderr = sliceTail(job.stderr, tail);
  const status = job.done ? `done (code=${job.exitCode})` : "running";
  const elapsed = Math.round((Date.now() - job.startedAt.getTime()) / 1000);
  return (
    `Job ${id} [${status}] elapsed=${elapsed}s\n` +
    `Command: ${job.command}\n` +
    `--- stdout (${job.stdout.length}b) ---\n${stdout || "(empty)"}\n` +
    `--- stderr (${job.stderr.length}b) ---\n${stderr || "(empty)"}`
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
