import { readFileSync, existsSync, statSync, unlinkSync } from "fs";
import { join, dirname, basename, resolve } from "path";
import { tmpdir } from "os";
import { randomBytes } from "crypto";
import { execFileSync } from "child_process";
import type { SFTPWrapper } from "ssh2";
import { state, addLog, DEFAULT_TRANSFER_TIMEOUT_MS } from "./state.js";
import { getSftp, runScript } from "./ssh-core.js";
import { saveTempFile, getTempFile, readTempFileContent } from "./temp.js";
import { formatBytes, formatPermissions, shellQuote, assertNotUnc } from "./utils.js";
import type { TempFile } from "./types.js";

function readAll(sftp: SFTPWrapper, remotePath: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    const rs = sftp.createReadStream(remotePath);
    rs.on("data", (chunk: Buffer) => chunks.push(chunk));
    rs.on("close", () => resolve(Buffer.concat(chunks)));
    rs.on("error", (e: Error) => { addLog("error", e.message); reject(e); });
  });
}

function writeAll(sftp: SFTPWrapper, remotePath: string, content: string | Buffer, mode?: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const ws = sftp.createWriteStream(remotePath, mode === undefined ? undefined : { mode });
    ws.on("close", () => resolve());
    ws.on("error", (e: Error) => { addLog("error", e.message); reject(e); });
    ws.end(content);
  });
}

/* Wraps one callback-style SFTP call; logs failures the same way everywhere. */
function sftpCall<T>(fn: (sftp: SFTPWrapper, cb: (e: Error | null | undefined, v?: T) => void) => void): Promise<T> {
  return getSftp().then(
    (sftp) =>
      new Promise<T>((resolve, reject) => {
        fn(sftp, (e, v) => {
          if (e) { addLog("error", e.message); return reject(e); }
          resolve(v as T);
        });
      })
  );
}

export async function sshUploadFile(localContent: string, remotePath: string): Promise<string> {
  await writeAll(await getSftp(), remotePath, localContent);
  addLog("info", `File written: ${remotePath}`);
  return `✅ File written: ${remotePath}`;
}

export async function sshReadFile(remotePath: string): Promise<string> {
  const content = (await readAll(await getSftp(), remotePath)).toString("utf-8");
  addLog("info", `File read: ${remotePath}`);
  return content;
}

export async function sshListDir(remotePath: string): Promise<string> {
  const list = await sftpCall<any[]>((sftp, cb) => sftp.readdir(remotePath, cb as any));
  const items = list.map((item) => {
    const type = item.attrs.isDirectory() ? "📁" : "📄";
    const size = item.attrs.size;
    const mtime = new Date(item.attrs.mtime * 1000).toISOString().substring(0, 10);
    return `${type} ${item.filename.padEnd(40)} ${String(size).padStart(10)} ${mtime}`;
  });
  addLog("info", `Directory read: ${remotePath} (${list.length})`);
  return items.join("\n") || "(empty directory)";
}

export interface DownloadResult {
  tempFile: TempFile;
  content: string;
  preview: string;
}

export async function sshDownloadFile(remotePath: string, asBase64 = false): Promise<DownloadResult> {
  const serverHost = state.session?.config.host || "unknown";
  const buffer = await readAll(await getSftp(), remotePath);
  const tempFile = saveTempFile(remotePath, buffer, serverHost);
  addLog("info", `Downloaded: ${remotePath} → ${tempFile.localPath} (${buffer.length}b)`);
  let content: string;
  let preview: string;
  if (asBase64) {
    content = buffer.toString("base64");
    preview = `[BASE64: ${content.length} chars]`;
  } else if (tempFile.isBinary) {
    content = buffer.toString("base64");
    preview = `[BINARY: ${buffer.length} bytes — base64 in temp]`;
  } else {
    content = buffer.toString("utf-8");
    const lines = content.split("\n");
    preview =
      lines.length > 200
        ? lines.slice(0, 200).join("\n") + `\n\n... ${lines.length - 200} more lines ...`
        : content;
  }
  return { tempFile, content, preview };
}

export async function sshUploadFromTemp(tempId: string, remotePath?: string): Promise<string> {
  const tempFile = getTempFile(tempId);
  if (!tempFile) throw new Error(`Temp file "${tempId}" not found`);
  const content = readTempFileContent(tempId);
  if (!content) throw new Error("Failed to read temp file");
  const targetPath = remotePath || tempFile.remotePath;
  await writeAll(await getSftp(), targetPath, content);
  addLog("info", `Uploaded from temp: ${tempFile.localPath} → ${targetPath}`);
  return `✅ Uploaded: ${targetPath} (${content.length}b)`;
}

export async function sshFileInfo(remotePath: string): Promise<string> {
  const stats = await sftpCall<any>((sftp, cb) => sftp.stat(remotePath, cb as any));
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
  addLog("info", `Stat: ${remotePath}`);
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

export async function sshMkdir(remotePath: string, recursive = false): Promise<string> {
  /* OpenSSH reports EEXIST as a generic "Failure", so an existing directory is detected by stat, not by message. */
  const tryMkdir = (path: string) =>
    sftpCall<void>((sftp, cb) =>
      sftp.mkdir(path, (mkErr: any) => {
        if (!mkErr) return cb(null);
        sftp.stat(path, (stErr, st) => cb(!stErr && st.isDirectory() ? null : mkErr));
      })
    );
  if (!recursive) {
    await tryMkdir(remotePath);
    addLog("info", `mkdir: ${remotePath}`);
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
  addLog("info", `mkdir -p: ${remotePath}`);
  return `✅ Created: ${remotePath}`;
}

export async function sshRename(oldPath: string, newPath: string): Promise<string> {
  await sftpCall<void>((sftp, cb) => sftp.rename(oldPath, newPath, cb));
  addLog("info", `rename: ${oldPath} → ${newPath}`);
  return `✅ ${oldPath} → ${newPath}`;
}

export async function sshChmod(remotePath: string, mode: string): Promise<string> {
  const modeNum = parseInt(mode, 8);
  if (isNaN(modeNum) || modeNum < 0 || modeNum > 0o777) {
    throw new Error(`Invalid mode: ${mode}. Use octal (e.g. 755).`);
  }
  await sftpCall<void>((sftp, cb) => sftp.chmod(remotePath, modeNum, cb));
  addLog("info", `chmod ${mode}: ${remotePath}`);
  return `✅ Mode ${mode}: ${remotePath}`;
}

export async function sshDelete(remotePath: string, isDirectory = false): Promise<string> {
  await sftpCall<void>((sftp, cb) => (isDirectory ? sftp.rmdir(remotePath, cb) : sftp.unlink(remotePath, cb)));
  addLog("info", `delete: ${remotePath}`);
  return `✅ Deleted: ${remotePath}`;
}

/* Stays under the tool-level transfer deadline so the command, not the whole session, is what times out. */
async function runChecked(script: string, timeoutMs = DEFAULT_TRANSFER_TIMEOUT_MS - 10_000): Promise<void> {
  const r = await runScript(script, timeoutMs);
  if (r.timedOut) throw new Error(`Timed out after ${r.limitMs} ms: ${script}`);
  if (r.code !== 0) throw new Error(r.stderr.trim() || r.stdout.trim() || `exit code ${r.code}`);
}

export async function sshCopy(srcPath: string, destPath: string): Promise<string> {
  await runChecked(`cp -r -- ${shellQuote(srcPath)} ${shellQuote(destPath)}`);
  addLog("info", `cp: ${srcPath} → ${destPath}`);
  return `✅ ${srcPath} → ${destPath}`;
}

export async function sshUpload(localPathArg: string, remotePath: string, exclude: string[] = []): Promise<string> {
  if (!state.session?.connected) throw new Error("No active SSH connection");
  const deadlineAt = Date.now() + DEFAULT_TRANSFER_TIMEOUT_MS - 10_000;
  const localPath = resolve(localPathArg);
  assertNotUnc(localPath, "upload");
  if (!existsSync(localPath)) throw new Error(`Local path not found: ${localPath}`);
  const stats = statSync(localPath);

  if (stats.isFile()) {
    const buffer = readFileSync(localPath);
    await writeAll(await getSftp(), remotePath, buffer);
    addLog("info", `File uploaded: ${localPath} → ${remotePath} (${buffer.length}b)`);
    return `✅ File uploaded: ${localPath} → ${remotePath} (${buffer.length}b)`;
  }
  if (!stats.isDirectory()) throw new Error(`Not a file or directory: ${localPath}`);

  /* Archive name is relative to cwd=tmpdir: GNU tar treats "C:..." in -f as a remote host. */
  const tarName = `ssh_upload_${randomBytes(8).toString("hex")}.tar.gz`;
  const tempTarPath = join(tmpdir(), tarName);
  const remoteTarPath = `/tmp/${tarName}`;
  try {
    addLog("info", `tar: ${localPath}`);
    execFileSync(
      "tar",
      ["-czf", tarName, ...exclude.map((p) => `--exclude=${p}`), "-C", dirname(localPath), "--", basename(localPath)],
      { cwd: tmpdir(), timeout: 120_000, stdio: "pipe" }
    );
    const tarBuffer = readFileSync(tempTarPath);
    addLog("info", `Archive: ${(tarBuffer.length / 1024).toFixed(1)} KB`);
    await writeAll(await getSftp(), remoteTarPath, tarBuffer, 0o600);
    const dest = shellQuote(remotePath);
    const tarQ = shellQuote(remoteTarPath);
    await runChecked(`mkdir -p -- ${dest} && tar -xzf ${tarQ} -C ${dest} --strip-components=1; rc=$?; rm -f ${tarQ}; exit $rc`, Math.max(deadlineAt - Date.now(), 1_000));
    addLog("info", `Directory uploaded: ${localPath} → ${remotePath}`);
    return [
      `✅ Directory uploaded: ${localPath} → ${remotePath}`,
      `📦 Archive size: ${(tarBuffer.length / 1024).toFixed(1)} KB`,
      exclude.length > 0 ? `🚫 Excluded: ${exclude.join(", ")}` : "",
    ].filter(Boolean).join("\n");
  } finally {
    try { unlinkSync(tempTarPath); } catch { /* ignore */ }
  }
}
