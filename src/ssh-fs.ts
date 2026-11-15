import { readFileSync, existsSync, statSync, unlinkSync, createReadStream, createWriteStream, openSync, readSync, closeSync, realpathSync } from "fs";
import type { WriteStream } from "fs";
import { join, dirname, basename, resolve, sep } from "path";
import { tmpdir } from "os";
import { randomBytes } from "crypto";
import { execFileSync } from "child_process";
import type { SFTPWrapper, FileEntryWithStats } from "ssh2";
import { addLog, DEFAULT_TRANSFER_TIMEOUT_MS } from "./state.js";
import type { Conn, SessionCtx } from "./state.js";
import { getSftp, runScript } from "./ssh-core.js";
import {
  getTempFile,
  tempQuotaLeft,
  prepareTempFile,
  addTempFile,
  REMOTE_TEMP_QUOTA_BYTES,
  REMOTE_INLINE_MAX_BYTES,
} from "./temp.js";
import { formatBytes, formatPermissions, shellQuote, assertNotUnc } from "./utils.js";
import type { TempFile } from "./types.js";

/* Remote mode: inline reads in flight per session, so parallel calls cannot multiply the per-call inline cap. */
const REMOTE_INFLIGHT_INLINE_BYTES = 4 * REMOTE_INLINE_MAX_BYTES;
/* Remote mode: a listing stops here; readdir(path) would keep every entry of a huge (or endless) directory. */
const REMOTE_LIST_MAX_ENTRIES = 10_000;
const SFTP_STATUS_EOF = 1;

export function inlineBusyMessage(): string {
  return `Too many file reads in progress in this session (${formatBytes(REMOTE_INFLIGHT_INLINE_BYTES)} at once); retry when they finish`;
}

/** Remote-mode reservation of bytes a whole-file read has buffered or written so far. After release() it takes
 * nothing more, so a read that outlives its call (deadline) cannot reserve bytes nobody will release. */
export class ReadBudget {
  private taken = 0;
  private closed = false;
  constructor(private readonly ctx: SessionCtx, private readonly kind: "inline" | "temp") {}
  take(n: number): boolean {
    const ctx = this.ctx;
    if (ctx.mode !== "remote") return true;
    if (this.closed) return false;
    const room = this.kind === "inline" ? REMOTE_INFLIGHT_INLINE_BYTES - ctx.inflight.inline : tempQuotaLeft(ctx);
    if (n > room) return false;
    ctx.inflight[this.kind] += n;
    this.taken += n;
    return true;
  }
  release(): void {
    this.ctx.inflight[this.kind] -= this.taken;
    this.taken = 0;
    this.closed = true;
  }
}

/* Whole file into memory, for content returned inline. Remote mode caps it per call and per session; with `hold`
 * the bytes stay reserved after the read, until the caller releases it. */
function readInline(conn: Conn, sftp: SFTPWrapper, remotePath: string, hold?: ReadBudget): Promise<Buffer> {
  const perCall = conn.ctx.mode === "remote" ? REMOTE_INLINE_MAX_BYTES : Infinity;
  const budget = hold ?? new ReadBudget(conn.ctx, "inline");
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    const rs = sftp.createReadStream(remotePath);
    const fail = (e: Error) => {
      if (settled) return;
      settled = true;
      chunks.length = 0;
      budget.release();
      rs.destroy();
      reject(e);
    };
    rs.on("data", (chunk: Buffer) => {
      if (settled) return;
      total += chunk.length;
      if (total > perCall) {
        fail(new Error(`${remotePath} is larger than the ${formatBytes(perCall)} remote mode returns inline; use ssh_execute (head, tail, sed -n) or ssh_download_file`));
        return;
      }
      if (!budget.take(chunk.length)) {
        fail(new Error(inlineBusyMessage()));
        return;
      }
      chunks.push(chunk);
    });
    rs.on("close", () => {
      if (settled) return;
      settled = true;
      if (!hold) budget.release();
      resolve(Buffer.concat(chunks));
    });
    rs.on("error", (e: Error) => { addLog(conn, "error", e.message); fail(e); });
  });
}

/* Streams a remote file into a local temp file, so a download never sits in memory. Remote mode charges every byte
 * against the session's temp quota as it arrives (parallel downloads share it); the caller releases the budget once
 * the file is registered. */
function downloadToFile(
  conn: Conn,
  sftp: SFTPWrapper,
  remotePath: string,
  localPath: string
): Promise<{ size: number; isBinary: boolean; budget: ReadBudget }> {
  const budget = new ReadBudget(conn.ctx, "temp");
  /* Local fs errors carry the host's temp path, which a remote client must not learn. */
  const localError = (e: Error) => (conn.ctx.mode === "remote" ? new Error(`Cannot store ${remotePath} in the temp store`) : e);
  return new Promise((resolve, reject) => {
    let size = 0;
    let isBinary = false;
    let settled = false;
    /* The local file first: if it cannot even be created, no remote file handle is opened (and left open). */
    let ws: WriteStream;
    try {
      ws = createWriteStream(localPath, { flags: "wx", mode: 0o600 });
    } catch (e) {
      reject(localError(e as Error));
      return;
    }
    const rs = sftp.createReadStream(remotePath);
    const fail = (e: Error) => {
      if (settled) return;
      settled = true;
      budget.release();
      rs.destroy();
      const remove = () => { try { unlinkSync(localPath); } catch { /* never created */ } };
      if (ws.closed) remove();
      else ws.once("close", remove);
      ws.destroy();
      reject(e);
    };
    rs.on("data", (chunk: Buffer) => {
      if (settled) return;
      if (!budget.take(chunk.length)) {
        fail(new Error(
          `${remotePath} does not fit in this session's temp store (${formatBytes(REMOTE_TEMP_QUOTA_BYTES)}, downloads in progress included); ` +
          `free space with ssh_temp_delete or ssh_temp_cleanup, or use ssh_execute (head, split)`
        ));
        return;
      }
      size += chunk.length;
      if (!isBinary && chunk.includes(0x00)) isBinary = true;
      if (!ws.write(chunk)) {
        rs.pause();
        ws.once("drain", () => rs.resume());
      }
    });
    rs.on("end", () => { if (!settled) ws.end(); });
    rs.on("error", (e: Error) => { addLog(conn, "error", e.message); fail(e); });
    ws.on("error", (e: Error) => fail(localError(e)));
    ws.on("close", () => {
      if (settled || !ws.writableFinished) return;
      settled = true;
      resolve({ size, isBinary, budget });
    });
  });
}

function readHead(path: string, n: number): Buffer {
  const buf = Buffer.alloc(n);
  const fd = openSync(path, "r");
  try {
    let got = 0;
    while (got < n) {
      const r = readSync(fd, buf, got, n - got, got);
      if (r === 0) break;
      got += r;
    }
    return got === n ? buf : buf.subarray(0, got);
  } finally {
    closeSync(fd);
  }
}

function writeAll(conn: Conn, sftp: SFTPWrapper, remotePath: string, content: string | Buffer, mode?: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const ws = sftp.createWriteStream(remotePath, mode === undefined ? undefined : { mode });
    ws.on("close", () => resolve());
    ws.on("error", (e: Error) => { addLog(conn, "error", e.message); reject(e); });
    ws.end(content);
  });
}

/* Wraps one callback-style SFTP call; logs failures the same way everywhere. */
function sftpCall<T>(conn: Conn, fn: (sftp: SFTPWrapper, cb: (e: Error | null | undefined, v?: T) => void) => void): Promise<T> {
  return getSftp(conn).then(
    (sftp) =>
      new Promise<T>((resolve, reject) => {
        fn(sftp, (e, v) => {
          if (e) { addLog(conn, "error", e.message); return reject(e); }
          resolve(v as T);
        });
      })
  );
}

export async function sshUploadFile(conn: Conn, localContent: string, remotePath: string): Promise<string> {
  await writeAll(conn, await getSftp(conn), remotePath, localContent);
  addLog(conn, "info", `File written: ${remotePath}`);
  return `✅ File written: ${remotePath}`;
}

export async function sshReadFile(conn: Conn, remotePath: string, hold?: ReadBudget): Promise<string> {
  const content = (await readInline(conn, await getSftp(conn), remotePath, hold)).toString("utf-8");
  addLog(conn, "info", `File read: ${remotePath}`);
  return content;
}

/* Remote mode: batch by batch through a handle, stopping at the entry or inline-size cap. */
async function readDirBounded(conn: Conn, remotePath: string): Promise<{ list: FileEntryWithStats[]; truncated: boolean }> {
  const sftp = await getSftp(conn);
  const handle = await sftpCall<Buffer>(conn, (s, cb) => s.opendir(remotePath, cb as any));
  const list: FileEntryWithStats[] = [];
  let bytes = 0;
  try {
    for (;;) {
      const batch = await new Promise<FileEntryWithStats[] | null>((resolve, reject) => {
        sftp.readdir(handle, (e: any, l) => {
          if (e && e.code === SFTP_STATUS_EOF) return resolve(null);
          if (e) { addLog(conn, "error", e.message); return reject(e); }
          resolve(l);
        });
      });
      if (!batch) return { list, truncated: false };
      for (const item of batch) {
        /* longname is the server's ls line (up to a whole SFTP packet each) and never shown: the budget counts filename. */
        list.push({ filename: item.filename, longname: "", attrs: item.attrs } as FileEntryWithStats);
        bytes += String(item.filename).length + 70;
        if (list.length >= REMOTE_LIST_MAX_ENTRIES || bytes >= REMOTE_INLINE_MAX_BYTES) return { list, truncated: true };
      }
    }
  } finally {
    sftp.close(handle, () => {});
  }
}

export async function sshListDir(conn: Conn, remotePath: string): Promise<string> {
  const { list, truncated } =
    conn.ctx.mode === "remote"
      ? await readDirBounded(conn, remotePath)
      : { list: await sftpCall<any[]>(conn, (sftp, cb) => sftp.readdir(remotePath, cb as any)), truncated: false };
  const items = list.map((item) => {
    const type = item.attrs.isDirectory() ? "📁" : "📄";
    const size = item.attrs.size;
    const mtime = new Date(item.attrs.mtime * 1000).toISOString().substring(0, 10);
    return `${type} ${item.filename.padEnd(40)} ${String(size).padStart(10)} ${mtime}`;
  });
  addLog(conn, "info", `Directory read: ${remotePath} (${list.length}${truncated ? ", truncated" : ""})`);
  const text = items.join("\n") || "(empty directory)";
  return truncated
    ? `${text}\n\n... listing cut at ${list.length} entries; list the rest with ssh_execute (ls | head, find -maxdepth 1) ...`
    : text;
}

/** Largest file ssh_download_file returns inline as base64 (a third larger on the way out), in both modes. */
export const INLINE_BASE64_MAX_BYTES = REMOTE_INLINE_MAX_BYTES;

export interface DownloadResult {
  tempFile: TempFile;
  preview: string;
  /** preview is the whole file as base64. */
  base64?: boolean;
}

/* Session logs reach the client; a remote client gets the temp id, not the host's filesystem path. */
function tempLabel(ctx: SessionCtx, tf: TempFile): string {
  return ctx.mode === "remote" ? `temp ${tf.id}` : tf.localPath;
}

export async function sshDownloadFile(conn: Conn, remotePath: string, asBase64 = false, hold?: ReadBudget): Promise<DownloadResult> {
  const ctx = conn.ctx;
  const serverHost = String(conn.session?.config.host || "unknown");
  const sftp = await getSftp(conn);
  const slot = prepareTempFile(ctx, remotePath);
  const { size, isBinary, budget } = await downloadToFile(conn, sftp, remotePath, slot.localPath);
  let tempFile: TempFile;
  try {
    tempFile = addTempFile(ctx, slot, remotePath, serverHost, size, isBinary);
    tempFile.connection = conn.name;
    tempFile.connectionKey = conn.key;
    const cfg = conn.session?.config;
    if (cfg) tempFile.endpoint = `${cfg.username}@${cfg.host}:${cfg.port || 22}`;
  } finally {
    budget.release();
  }
  addLog(conn, "info", `Downloaded: ${remotePath} → ${tempLabel(ctx, tempFile)} (${size}b)`);
  const elsewhere =
    ctx.mode === "remote"
      ? "read it in parts on the server with ssh_execute (dd or split, then base64)"
      : "use the local path above, or ssh_temp_read {temp_id, as_base64: true}";
  if (asBase64) {
    if (size > INLINE_BASE64_MAX_BYTES) {
      return { tempFile, preview: `[base64 not returned inline: ${formatBytes(size)} is over the ${formatBytes(INLINE_BASE64_MAX_BYTES)} inline limit. The file is in the temp store; ${elsewhere}]` };
    }
    if (hold && !hold.take(size)) {
      return { tempFile, preview: `[base64 skipped: ${inlineBusyMessage()}; read it with ssh_temp_read {temp_id, as_base64: true}]` };
    }
    return { tempFile, preview: readHead(tempFile.localPath, size).toString("base64"), base64: true };
  }
  if (isBinary) return { tempFile, preview: `[BINARY: ${size} bytes, not shown; pass as_base64: true for the content (up to ${formatBytes(INLINE_BASE64_MAX_BYTES)}), or ssh_temp_read {temp_id, as_base64: true}]` };
  /* Remote mode returns at most the inline cap; the rest stays in the temp store. */
  const headBytes = ctx.mode === "remote" ? Math.min(size, REMOTE_INLINE_MAX_BYTES) : size;
  if (hold && !hold.take(headBytes)) {
    return { tempFile, preview: `[preview skipped: ${inlineBusyMessage()}; read it with ssh_temp_read]` };
  }
  const head = readHead(tempFile.localPath, headBytes);
  const cut = head.length < size;
  const lines = head.toString("utf-8").split("\n");
  let preview: string;
  if (lines.length > 200) {
    preview = lines.slice(0, 200).join("\n") + (cut ? `\n\n... more lines ...` : `\n\n... ${lines.length - 200} more lines ...`);
  } else {
    preview = lines.join("\n") + (cut ? `\n\n... preview cut at ${formatBytes(head.length)} of ${formatBytes(size)}; read further with ssh_execute (sed -n, tail) ...` : "");
  }
  return { tempFile, preview };
}

/* Streams a temp file to the server, so an upload never holds the whole file in memory. */
function uploadFile(conn: Conn, sftp: SFTPWrapper, localPath: string, remotePath: string): Promise<number> {
  return new Promise((resolve, reject) => {
    let size = 0;
    let settled = false;
    const done = (e?: Error) => {
      if (settled) return;
      settled = true;
      if (e) reject(e);
      else resolve(size);
    };
    const rs = createReadStream(localPath);
    const ws = sftp.createWriteStream(remotePath);
    rs.on("data", (c: Buffer) => { size += c.length; });
    rs.on("error", (e: Error) => { ws.destroy(); done(e); });
    ws.on("error", (e: Error) => { addLog(conn, "error", e.message); rs.destroy(); done(e); });
    ws.on("close", () => done());
    rs.pipe(ws);
  });
}

export async function sshUploadFromTemp(conn: Conn, tempId: string, remotePath?: string): Promise<string> {
  const tempFile = getTempFile(conn.ctx, tempId);
  if (!tempFile) throw new Error(`Temp file "${tempId}" not found`);
  if (!existsSync(tempFile.localPath)) throw new Error("Failed to read temp file");
  const targetPath = remotePath || tempFile.remotePath;
  const size = await uploadFile(conn, await getSftp(conn), tempFile.localPath, targetPath);
  addLog(conn, "info", `Uploaded from temp: ${tempLabel(conn.ctx, tempFile)} → ${targetPath}`);
  return `✅ Uploaded: ${targetPath} on ${conn.name} (${size}b)`;
}

export async function sshFileInfo(conn: Conn, remotePath: string): Promise<string> {
  const stats = await sftpCall<any>(conn, (sftp, cb) => sftp.stat(remotePath, cb as any));
  const type = stats.isDirectory()
    ? "📁 Directory"
    : stats.isFile()
      ? "📄 File"
      : stats.isSymbolicLink()
        ? "🔗 Symlink"
        : "❓ Unknown";
  const mode = (stats.mode & 0o777).toString(8).padStart(3, "0");
  const mtime = new Date(stats.mtime * 1000).toISOString();
  const atime = new Date(stats.atime * 1000).toISOString();
  addLog(conn, "info", `Stat: ${remotePath}`);
  return [
    `📋 ${remotePath}`,
    ``,
    `Type: ${type}`,
    `Size: ${stats.size} b (${formatBytes(stats.size)})`,
    `Perms: ${mode} (${formatPermissions(stats.mode)})`,
    `UID: ${stats.uid}  GID: ${stats.gid}`,
    `Modified: ${mtime}`,
    `Accessed: ${atime}`,
  ].join("\n");
}

export async function sshMkdir(conn: Conn, remotePath: string, recursive = false): Promise<string> {
  /* OpenSSH reports EEXIST as a generic "Failure", so an existing directory is detected by stat, not by message. */
  const tryMkdir = (path: string) =>
    sftpCall<void>(conn, (sftp, cb) =>
      sftp.mkdir(path, (mkErr: any) => {
        if (!mkErr) return cb(null);
        sftp.stat(path, (stErr, st) => cb(!stErr && st.isDirectory() ? null : mkErr));
      })
    );
  if (!recursive) {
    await tryMkdir(remotePath);
    addLog(conn, "info", `mkdir: ${remotePath}`);
    return `✅ Created: ${remotePath}`;
  }
  const norm = remotePath.replace(/\\/g, "/").replace(/\/+$/, "");
  const isAbsWin = /^[A-Za-z]:\//.test(norm);
  const prefix = norm.startsWith("/") ? "/" : "";
  const parts = norm.split("/").filter(Boolean);
  let acc = isAbsWin ? parts.shift() || "" : "";
  for (const part of parts) {
    acc = acc ? acc + "/" + part : prefix + part;
    await tryMkdir(acc);
  }
  addLog(conn, "info", `mkdir -p: ${remotePath}`);
  return `✅ Created: ${remotePath}`;
}

export async function sshRename(conn: Conn, oldPath: string, newPath: string): Promise<string> {
  await sftpCall<void>(conn, (sftp, cb) => sftp.rename(oldPath, newPath, cb));
  addLog(conn, "info", `rename: ${oldPath} → ${newPath}`);
  return `✅ ${oldPath} → ${newPath}`;
}

export async function sshChmod(conn: Conn, remotePath: string, mode: string): Promise<string> {
  const modeNum = parseInt(mode, 8);
  if (isNaN(modeNum) || modeNum < 0 || modeNum > 0o777) {
    throw new Error(`Invalid mode: ${mode}. Use octal (e.g. 755).`);
  }
  await sftpCall<void>(conn, (sftp, cb) => sftp.chmod(remotePath, modeNum, cb));
  addLog(conn, "info", `chmod ${mode}: ${remotePath}`);
  return `✅ Mode ${mode}: ${remotePath}`;
}

export async function sshDelete(conn: Conn, remotePath: string, isDirectory = false): Promise<string> {
  await sftpCall<void>(conn, (sftp, cb) => (isDirectory ? sftp.rmdir(remotePath, cb) : sftp.unlink(remotePath, cb)));
  addLog(conn, "info", `delete: ${remotePath}`);
  return `✅ Deleted: ${remotePath}`;
}

/* Stays under the tool-level transfer deadline so the command, not the whole session, is what times out. */
async function runChecked(conn: Conn, script: string, timeoutMs = DEFAULT_TRANSFER_TIMEOUT_MS - 10_000): Promise<void> {
  const r = await runScript(conn, script, timeoutMs);
  /* Not the script: it can carry secrets, and this message reaches the session log. */
  if (r.timedOut) throw new Error(`Timed out after ${r.limitMs} ms`);
  if (r.code !== 0) throw new Error(r.stderr.trim() || r.stdout.trim() || `exit code ${r.code}`);
}

export async function sshCopy(conn: Conn, srcPath: string, destPath: string): Promise<string> {
  await runChecked(conn, `cp -r -- ${shellQuote(srcPath)} ${shellQuote(destPath)}`);
  addLog(conn, "info", `cp: ${srcPath} → ${destPath}`);
  return `✅ ${srcPath} → ${destPath}`;
}

/* The profile store and its key files must never reach a server: ssh_read_file would hand every stored secret to
 * the model. Also refuses the store's lock/temp siblings and any directory containing one of them. */
function assertNotSecret(ctx: SessionCtx, localPath: string, isDirectory: boolean): void {
  const norm = (p: string) => {
    let r = resolve(p);
    try { r = realpathSync(r); } catch { /* not there (yet): compare the path as given */ }
    return process.platform === "win32" ? r.toLowerCase() : r;
  };
  const target = norm(localPath);
  for (const raw of ctx.store.protectedPaths?.() ?? []) {
    const p = norm(raw);
    const sibling = target.startsWith(p + ".") && /\.(lock|tmp)$/.test(target);
    const inside = isDirectory && p.startsWith(target.endsWith(sep) ? target : target + sep);
    if (target === p || sibling || inside) {
      throw new Error(`Refusing to upload ${localPath}: it is or contains the profile store or a profile's key file`);
    }
  }
}

export async function sshUpload(conn: Conn, localPathArg: string, remotePath: string, exclude: string[] = []): Promise<string> {
  if (!conn.session?.connected) throw new Error(`No active SSH connection to ${conn.name}`);
  const deadlineAt = Date.now() + DEFAULT_TRANSFER_TIMEOUT_MS - 10_000;
  const localPath = resolve(localPathArg);
  assertNotUnc(localPath, "upload");
  if (!existsSync(localPath)) throw new Error(`Local path not found: ${localPath}`);
  const stats = statSync(localPath);
  assertNotSecret(conn.ctx, localPath, stats.isDirectory());

  if (stats.isFile()) {
    const buffer = readFileSync(localPath);
    await writeAll(conn, await getSftp(conn), remotePath, buffer);
    addLog(conn, "info", `File uploaded: ${localPath} → ${remotePath} (${buffer.length}b)`);
    return `✅ File uploaded: ${localPath} → ${remotePath} (${buffer.length}b)`;
  }
  if (!stats.isDirectory()) throw new Error(`Not a file or directory: ${localPath}`);

  /* Archive name is relative to cwd=tmpdir: GNU tar treats "C:..." in -f as a remote host. */
  const tarName = `ssh_upload_${randomBytes(8).toString("hex")}.tar.gz`;
  const tempTarPath = join(tmpdir(), tarName);
  const remoteTarPath = `/tmp/${tarName}`;
  try {
    addLog(conn, "info", `tar: ${localPath}`);
    execFileSync(
      "tar",
      ["-czf", tarName, ...exclude.map((p) => `--exclude=${p}`), "-C", dirname(localPath), "--", basename(localPath)],
      { cwd: tmpdir(), timeout: 120_000, stdio: "pipe" }
    );
    const tarBuffer = readFileSync(tempTarPath);
    addLog(conn, "info", `Archive: ${(tarBuffer.length / 1024).toFixed(1)} KB`);
    await writeAll(conn, await getSftp(conn), remoteTarPath, tarBuffer, 0o600);
    const dest = shellQuote(remotePath);
    const tarQ = shellQuote(remoteTarPath);
    await runChecked(conn, `mkdir -p -- ${dest} && tar -xzf ${tarQ} -C ${dest} --strip-components=1; rc=$?; rm -f ${tarQ}; exit $rc`, Math.max(deadlineAt - Date.now(), 1_000));
    addLog(conn, "info", `Directory uploaded: ${localPath} → ${remotePath}`);
    return [
      `✅ Directory uploaded: ${localPath} → ${remotePath}`,
      `📦 Archive size: ${(tarBuffer.length / 1024).toFixed(1)} KB`,
      exclude.length > 0 ? `🚫 Excluded: ${exclude.join(", ")}` : "",
    ].filter(Boolean).join("\n");
  } finally {
    try { unlinkSync(tempTarPath); } catch { /* ignore */ }
  }
}
