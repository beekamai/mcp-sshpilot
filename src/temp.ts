import { existsSync, mkdirSync, mkdtempSync, writeFileSync, readFileSync, unlinkSync, lstatSync, chmodSync } from "fs";
import { join, basename } from "path";
import { tmpdir } from "os";
import type { TempFile } from "./types.js";
import type { SessionCtx } from "./state.js";
import { generateTempId } from "./utils.js";

/** Shared temp directory of stdio mode, one per OS user on POSIX; remote sessions get a private one each. */
export const TEMP_DIR = join(tmpdir(), typeof process.getuid === "function" ? `mcp-sshpilot-files-${process.getuid()}` : "mcp-sshpilot-files");

/** Per-session cap of the temp store in remote mode, where many sessions share one host's disk and memory. */
export const REMOTE_TEMP_QUOTA_BYTES = 64 * 1024 * 1024;
/** Largest file content remote mode returns inline in one tool result; JSON escaping can grow it up to 6x on the way out. */
export const REMOTE_INLINE_MAX_BYTES = 2 * 1024 * 1024;
/** Per-session cap of temp entries in remote mode: empty files cost no quota bytes but still an entry and an inode. */
export const REMOTE_MAX_TEMP_FILES = 256;

/** All remote sessions of the process together: 16 sessions x 64 MiB would pass the service memory limit when the
 * temp dir is a tmpfs (whose pages count against the service). */
export const REMOTE_TEMP_TOTAL_BYTES = 256 * 1024 * 1024;

/* Bytes held by the temp files of every remote session, kept in step by the functions below (the only writers). */
let remoteTempBytes = 0;

function account(ctx: SessionCtx, delta: number): void {
  if (ctx.mode === "remote") remoteTempBytes = Math.max(0, remoteTempBytes + delta);
}

function usedBytes(ctx: SessionCtx, exceptId?: string): number {
  let total = 0;
  for (const tf of ctx.tempFiles.values()) if (tf.id !== exceptId) total += tf.size;
  return total;
}

/** Bytes the temp store may still take in this session, downloads in progress included (Infinity in stdio mode). */
export function tempQuotaLeft(ctx: SessionCtx, replacingId?: string): number {
  if (ctx.mode !== "remote") return Infinity;
  const replaced = replacingId ? ctx.tempFiles.get(replacingId)?.size ?? 0 : 0;
  const session = REMOTE_TEMP_QUOTA_BYTES - usedBytes(ctx, replacingId) - ctx.inflight.temp;
  const total = REMOTE_TEMP_TOTAL_BYTES - (remoteTempBytes - replaced) - ctx.inflight.temp;
  return Math.max(0, Math.min(session, total));
}

function assertFits(ctx: SessionCtx, size: number, replacingId?: string): void {
  if (size > tempQuotaLeft(ctx, replacingId)) {
    throw new Error(
      `Temp store limit reached (${REMOTE_TEMP_QUOTA_BYTES / 1024 / 1024} MiB per session, ${REMOTE_TEMP_TOTAL_BYTES / 1024 / 1024} MiB for all sessions); free space with ssh_temp_delete or ssh_temp_cleanup`
    );
  }
}

/* The directory must be this user's alone: in a world-writable /tmp another local user could pre-create it (or
 * recreate one a tmp cleaner removed), swap a downloaded file before ssh_temp_upload or plant a symlink for
 * ssh_temp_read. lstat, so a symlink is never a directory here. Windows tmpdirs are per user. */
function isPrivateDir(dir: string): boolean {
  if (typeof process.getuid !== "function") return true;
  const st = lstatSync(dir);
  if (!st.isDirectory() || st.uid !== process.getuid()) return false;
  if ((st.mode & 0o077) !== 0) chmodSync(dir, 0o700);
  return true;
}

function ensureTempDir(ctx: SessionCtx): string {
  /* A download finishing after destroyCtx would recreate the removed private dir and leave it behind. */
  if (ctx.destroyed) throw new Error("Session is closed");
  if (ctx.tempDir && !existsSync(ctx.tempDir)) mkdirSync(ctx.tempDir, { recursive: true, mode: 0o700 });
  if (!ctx.tempDir || !isPrivateDir(ctx.tempDir)) {
    /* Taken by someone else: files of this session go to a fresh private directory, removed with the session. */
    ctx.tempDir = mkdtempSync(join(tmpdir(), "mcp-sshpilot-"));
    ctx.ownsTempDir = true;
  }
  return ctx.tempDir;
}

export interface TempSlot {
  id: string;
  filename: string;
  localPath: string;
}

/** A local path for a file the caller streams in; register it with addTempFile once it is complete. */
export function prepareTempFile(ctx: SessionCtx, remotePath: string): TempSlot {
  if (ctx.mode === "remote" && ctx.tempFiles.size >= REMOTE_MAX_TEMP_FILES) {
    throw new Error(`Temp store holds ${REMOTE_MAX_TEMP_FILES} files, the per-session limit; free some with ssh_temp_delete or ssh_temp_cleanup`);
  }
  const dir = ensureTempDir(ctx);
  const id = generateTempId();
  const filename = basename(remotePath);
  /* Remote mode never shows the local path, so the client's file name (NUL, 255+ bytes) need not be a valid one here. */
  return { id, filename, localPath: join(dir, ctx.mode === "remote" ? id : `${id}_${filename}`) };
}

export function addTempFile(ctx: SessionCtx, slot: TempSlot, remotePath: string, serverHost: string, size: number, isBinary: boolean): TempFile {
  const tempFile: TempFile = {
    id: slot.id,
    localPath: slot.localPath,
    remotePath,
    serverHost,
    filename: slot.filename,
    size,
    isBinary,
    downloadedAt: new Date(),
  };
  ctx.tempFiles.set(slot.id, tempFile);
  account(ctx, size);
  return tempFile;
}

export function saveTempFile(ctx: SessionCtx, remotePath: string, content: Buffer, serverHost: string): TempFile {
  assertFits(ctx, content.length);
  const slot = prepareTempFile(ctx, remotePath);
  writeFileSync(slot.localPath, content);
  return addTempFile(ctx, slot, remotePath, serverHost, content.length, content.includes(0x00));
}

export function getTempFile(ctx: SessionCtx, id: string): TempFile | undefined {
  return ctx.tempFiles.get(id);
}

export function listTempFiles(ctx: SessionCtx): TempFile[] {
  return Array.from(ctx.tempFiles.values());
}

export function readTempFileContent(ctx: SessionCtx, id: string): Buffer | null {
  const tf = ctx.tempFiles.get(id);
  if (!tf || !existsSync(tf.localPath)) return null;
  return readFileSync(tf.localPath) as unknown as Buffer;
}

export function updateTempFile(ctx: SessionCtx, id: string, content: Buffer): boolean {
  const tf = ctx.tempFiles.get(id);
  if (!tf) return false;
  assertFits(ctx, content.length, id);
  writeFileSync(tf.localPath, content);
  account(ctx, content.length - tf.size);
  tf.size = content.length;
  return true;
}

export function deleteTempFile(ctx: SessionCtx, id: string): boolean {
  const tf = ctx.tempFiles.get(id);
  if (!tf) return false;
  try {
    if (existsSync(tf.localPath)) unlinkSync(tf.localPath);
    ctx.tempFiles.delete(id);
    account(ctx, -tf.size);
    return true;
  } catch {
    return false;
  }
}

export function cleanupAllTempFiles(ctx: SessionCtx): number {
  let count = 0;
  for (const [id, tf] of ctx.tempFiles) {
    try {
      if (existsSync(tf.localPath)) unlinkSync(tf.localPath);
      ctx.tempFiles.delete(id);
      account(ctx, -tf.size);
      count++;
    } catch {
      /* A closing session drops the entry anyway (its directory is removed next), so release its bytes too. */
      if (ctx.destroyed) account(ctx, -tf.size);
    }
  }
  return count;
}
