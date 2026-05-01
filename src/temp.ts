import { existsSync, mkdirSync, writeFileSync, readFileSync, unlinkSync } from "fs";
import { join, basename } from "path";
import { tmpdir } from "os";
import type { TempFile } from "./types.js";
import { generateTempId } from "./utils.js";

export const TEMP_DIR = join(tmpdir(), "mcp-sshpilot-files");

const tempFiles: Map<string, TempFile> = new Map();

function ensureTempDir(): void {
  if (!existsSync(TEMP_DIR)) mkdirSync(TEMP_DIR, { recursive: true });
}

export function saveTempFile(remotePath: string, content: Buffer, serverHost: string): TempFile {
  ensureTempDir();
  const id = generateTempId();
  const filename = basename(remotePath);
  const isBinary = content.includes(0x00);
  const localPath = join(TEMP_DIR, `${id}_${filename}`);
  writeFileSync(localPath, content);
  const tempFile: TempFile = {
    id,
    localPath,
    remotePath,
    serverHost,
    filename,
    size: content.length,
    isBinary,
    downloadedAt: new Date(),
  };
  tempFiles.set(id, tempFile);
  return tempFile;
}

export function getTempFile(id: string): TempFile | undefined {
  return tempFiles.get(id);
}

export function listTempFiles(): TempFile[] {
  return Array.from(tempFiles.values());
}

export function readTempFileContent(id: string): Buffer | null {
  const tf = tempFiles.get(id);
  if (!tf || !existsSync(tf.localPath)) return null;
  return readFileSync(tf.localPath) as unknown as Buffer;
}

export function updateTempFile(id: string, content: Buffer): boolean {
  const tf = tempFiles.get(id);
  if (!tf) return false;
  writeFileSync(tf.localPath, content);
  tf.size = content.length;
  return true;
}

export function deleteTempFile(id: string): boolean {
  const tf = tempFiles.get(id);
  if (!tf) return false;
  try {
    if (existsSync(tf.localPath)) unlinkSync(tf.localPath);
    tempFiles.delete(id);
    return true;
  } catch {
    return false;
  }
}

export function cleanupAllTempFiles(): number {
  let count = 0;
  for (const [id, tf] of tempFiles) {
    try {
      if (existsSync(tf.localPath)) unlinkSync(tf.localPath);
      tempFiles.delete(id);
      count++;
    } catch {
      /* ignore */
    }
  }
  return count;
}
