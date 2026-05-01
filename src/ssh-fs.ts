import { readFileSync, existsSync, statSync, unlinkSync } from "fs";
import { join, dirname, basename } from "path";
import { tmpdir } from "os";
import { execSync } from "child_process";
import { state, addLog } from "./state.js";
import { sshExecute } from "./ssh-core.js";
import { saveTempFile, getTempFile, readTempFileContent } from "./temp.js";
import { formatBytes, formatPermissions } from "./utils.js";
import type { TempFile } from "./types.js";

export async function sshUploadFile(localContent: string, remotePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!state.session?.connected) return reject(new Error("No active SSH connection"));
    state.session.client.sftp((err, sftp) => {
      if (err) { addLog("error", `SFTP: ${err.message}`); return reject(err); }
      const ws = sftp.createWriteStream(remotePath);
      ws.on("close", () => {
        addLog("info", `File written: ${remotePath}`);
        resolve(`✅ File written: ${remotePath}`);
      });
      ws.on("error", (e: Error) => { addLog("error", e.message); reject(e); });
      ws.write(localContent);
      ws.end();
    });
  });
}

export async function sshReadFile(remotePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!state.session?.connected) return reject(new Error("No active SSH connection"));
    state.session.client.sftp((err, sftp) => {
      if (err) { addLog("error", `SFTP: ${err.message}`); return reject(err); }
      let content = "";
      const rs = sftp.createReadStream(remotePath);
      rs.on("data", (chunk: Buffer) => { content += chunk.toString(); });
      rs.on("close", () => {
        addLog("info", `File read: ${remotePath}`);
        resolve(content);
      });
      rs.on("error", (e: Error) => { addLog("error", e.message); reject(e); });
    });
  });
}

export async function sshListDir(remotePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!state.session?.connected) return reject(new Error("No active SSH connection"));
    state.session.client.sftp((err, sftp) => {
      if (err) { addLog("error", `SFTP: ${err.message}`); return reject(err); }
      sftp.readdir(remotePath, (e, list) => {
        if (e) { addLog("error", e.message); return reject(e); }
        const items = list.map((item) => {
          const type = item.attrs.isDirectory() ? "📁" : "📄";
          const size = item.attrs.size;
          const mtime = new Date(item.attrs.mtime * 1000).toISOString().substring(0, 10);
          return `${type} ${item.filename.padEnd(40)} ${String(size).padStart(10)} ${mtime}`;
        });
        addLog("info", `Directory read: ${remotePath} (${list.length})`);
        resolve(items.join("\n") || "(empty directory)");
      });
    });
  });
}

export interface DownloadResult {
  tempFile: TempFile;
  content: string;
  preview: string;
}

export async function sshDownloadFile(remotePath: string, asBase64 = false): Promise<DownloadResult> {
  return new Promise((resolve, reject) => {
    if (!state.session?.connected) return reject(new Error("No active SSH connection"));
    const serverHost = state.session.config.host || "unknown";
    state.session.client.sftp((err, sftp) => {
      if (err) { addLog("error", `SFTP: ${err.message}`); return reject(err); }
      const chunks: Buffer[] = [];
      const rs = sftp.createReadStream(remotePath);
      rs.on("data", (chunk: Buffer) => chunks.push(chunk));
      rs.on("close", () => {
        const buffer = Buffer.concat(chunks);
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
        resolve({ tempFile, content, preview });
      });
      rs.on("error", (e: Error) => { addLog("error", e.message); reject(e); });
    });
  });
}

export async function sshUploadFromTemp(tempId: string, remotePath?: string): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!state.session?.connected) return reject(new Error("No active SSH connection"));
    const tempFile = getTempFile(tempId);
    if (!tempFile) return reject(new Error(`Temp file "${tempId}" not found`));
    const content = readTempFileContent(tempId);
    if (!content) return reject(new Error("Failed to read temp file"));
    const targetPath = remotePath || tempFile.remotePath;
    state.session.client.sftp((err, sftp) => {
      if (err) { addLog("error", `SFTP: ${err.message}`); return reject(err); }
      const ws = sftp.createWriteStream(targetPath);
      ws.on("close", () => {
        addLog("info", `Uploaded from temp: ${tempFile.localPath} → ${targetPath}`);
        resolve(`✅ Uploaded: ${targetPath} (${content.length}b)`);
      });
      ws.on("error", (e: Error) => { addLog("error", e.message); reject(e); });
      ws.write(content);
      ws.end();
    });
  });
}

export async function sshFileInfo(remotePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!state.session?.connected) return reject(new Error("No active SSH connection"));
    state.session.client.sftp((err, sftp) => {
      if (err) { addLog("error", `SFTP: ${err.message}`); return reject(err); }
      sftp.stat(remotePath, (e, stats) => {
        if (e) { addLog("error", e.message); return reject(e); }
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
        const info = [
          `📋 ${remotePath}`,
          ``,
          `Type: ${type}`,
          `Size: ${stats.size} b (${formatBytes(stats.size)})`,
          `Perms: ${mode} (${formatPermissions(stats.mode)})`,
          `UID: ${stats.uid}  GID: ${stats.gid}`,
          `Modified: ${mtime}`,
          `Accessed: ${atime}`,
        ].join("\n");
        addLog("info", `Stat: ${remotePath}`);
        resolve(info);
      });
    });
  });
}

export async function sshMkdir(remotePath: string, recursive = false): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!state.session?.connected) return reject(new Error("No active SSH connection"));
    state.session.client.sftp((err, sftp) => {
      if (err) { addLog("error", `SFTP: ${err.message}`); return reject(err); }
      const tryMkdir = (path: string, cb: (e: Error | null) => void) => {
        sftp.mkdir(path, (mkErr: any) => {
          if (!mkErr) return cb(null);
          const msg = (mkErr.message || "").toLowerCase();
          if (msg.includes("already exists")) return cb(null);
          cb(mkErr);
        });
      };
      if (!recursive) {
        return tryMkdir(remotePath, (e) => {
          if (e) { addLog("error", e.message); return reject(e); }
          addLog("info", `mkdir: ${remotePath}`);
          resolve(`✅ Created: ${remotePath}`);
        });
      }
      const norm = remotePath.replace(/\\/g, "/").replace(/\/+$/, "");
      const isAbsWin = /^[A-Za-z]:\//.test(norm);
      const isAbsPosix = norm.startsWith("/");
      const parts = norm.split("/").filter(Boolean);
      let acc = "";
      if (isAbsWin) acc = parts.shift() || "";
      const prefix = isAbsPosix ? "/" : "";
      const mkNext = (i: number) => {
        if (i >= parts.length) {
          addLog("info", `mkdir -p: ${remotePath}`);
          return resolve(`✅ Created: ${remotePath}`);
        }
        acc = acc ? acc + "/" + parts[i] : prefix + parts[i];
        tryMkdir(acc, (e) => {
          if (e) { addLog("error", `mkdir '${acc}': ${e.message}`); return reject(e); }
          mkNext(i + 1);
        });
      };
      mkNext(0);
    });
  });
}

export async function sshRename(oldPath: string, newPath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!state.session?.connected) return reject(new Error("No active SSH connection"));
    state.session.client.sftp((err, sftp) => {
      if (err) { addLog("error", `SFTP: ${err.message}`); return reject(err); }
      sftp.rename(oldPath, newPath, (e) => {
        if (e) { addLog("error", e.message); return reject(e); }
        addLog("info", `rename: ${oldPath} → ${newPath}`);
        resolve(`✅ ${oldPath} → ${newPath}`);
      });
    });
  });
}

export async function sshChmod(remotePath: string, mode: string): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!state.session?.connected) return reject(new Error("No active SSH connection"));
    const modeNum = parseInt(mode, 8);
    if (isNaN(modeNum) || modeNum < 0 || modeNum > 0o777) {
      return reject(new Error(`Invalid mode: ${mode}. Use octal (e.g. 755).`));
    }
    state.session.client.sftp((err, sftp) => {
      if (err) { addLog("error", `SFTP: ${err.message}`); return reject(err); }
      sftp.chmod(remotePath, modeNum, (e) => {
        if (e) { addLog("error", e.message); return reject(e); }
        addLog("info", `chmod ${mode}: ${remotePath}`);
        resolve(`✅ Mode ${mode}: ${remotePath}`);
      });
    });
  });
}

export async function sshDelete(remotePath: string, isDirectory = false): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!state.session?.connected) return reject(new Error("No active SSH connection"));
    state.session.client.sftp((err, sftp) => {
      if (err) { addLog("error", `SFTP: ${err.message}`); return reject(err); }
      const handler = (e: Error | null | undefined) => {
        if (e) { addLog("error", e.message); return reject(e); }
        addLog("info", `delete: ${remotePath}`);
        resolve(`✅ Deleted: ${remotePath}`);
      };
      if (isDirectory) sftp.rmdir(remotePath, handler);
      else sftp.unlink(remotePath, handler);
    });
  });
}

export async function sshCopy(srcPath: string, destPath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!state.session?.connected) return reject(new Error("No active SSH connection"));
    state.session.client.exec(`cp -r "${srcPath}" "${destPath}"`, (err, stream) => {
      if (err) { addLog("error", err.message); return reject(err); }
      let stderr = "";
      stream.on("close", (code: number) => {
        if (code !== 0) return reject(new Error(stderr || `cp exit ${code}`));
        addLog("info", `cp: ${srcPath} → ${destPath}`);
        resolve(`✅ ${srcPath} → ${destPath}`);
      });
      stream.stderr.on("data", (d: Buffer) => { stderr += d.toString(); });
    });
  });
}

async function sshUploadBinary(buffer: Buffer, remotePath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    if (!state.session?.connected) return reject(new Error("No active SSH connection"));
    state.session.client.sftp((err, sftp) => {
      if (err) { addLog("error", `SFTP: ${err.message}`); return reject(err); }
      const ws = sftp.createWriteStream(remotePath);
      ws.on("close", () => resolve());
      ws.on("error", (e: Error) => reject(e));
      ws.end(buffer);
    });
  });
}

export async function sshUpload(localPath: string, remotePath: string, exclude: string[] = []): Promise<string> {
  if (!state.session?.connected) throw new Error("No active SSH connection");
  if (!existsSync(localPath)) throw new Error(`Local path not found: ${localPath}`);
  const stats = statSync(localPath);

  if (stats.isFile()) {
    const buffer = readFileSync(localPath);
    await sshUploadBinary(buffer, remotePath);
    addLog("info", `File uploaded: ${localPath} → ${remotePath} (${buffer.length}b)`);
    return `✅ File uploaded: ${localPath} → ${remotePath} (${buffer.length}b)`;
  }
  if (!stats.isDirectory()) throw new Error(`Not a file or directory: ${localPath}`);

  const ts = Date.now();
  const tempTarPath = join(tmpdir(), `ssh_upload_${ts}.tar.gz`);
  const remoteTarPath = `/tmp/ssh_upload_${ts}.tar.gz`;
  try {
    const parentDir = dirname(localPath).replace(/\\/g, "/");
    const dirName = basename(localPath);
    const excludeFlags = exclude.map((p) => `--exclude="${p}"`).join(" ");
    addLog("info", `tar: ${localPath}`);
    execSync(
      `tar -czf "${tempTarPath.replace(/\\/g, "/")}" ${excludeFlags} -C "${parentDir}" "${dirName}"`,
      { timeout: 120_000, stdio: "pipe" }
    );
    const tarBuffer = readFileSync(tempTarPath);
    addLog("info", `Archive: ${(tarBuffer.length / 1024).toFixed(1)} KB`);
    await sshUploadBinary(tarBuffer, remoteTarPath);
    await sshExecute(
      `mkdir -p "${remotePath}" && tar -xzf "${remoteTarPath}" -C "${remotePath}" --strip-components=1 && rm -f "${remoteTarPath}"`
    );
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
