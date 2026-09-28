import { StringDecoder } from "string_decoder";
import type { LogEntry } from "./types.js";

export function generateId(): string {
  return Math.random().toString(36).substring(2, 10);
}

/** Rejects UNC paths on Windows: touching one authenticates to that host over SMB and leaks the NTLM hash. */
export function assertNotUnc(p: string, what: string): void {
  if (process.platform === "win32" && /^[\\/]{2}/.test(p)) {
    throw new Error(`Network (UNC) ${what} paths are not allowed: ${p}`);
  }
}

/** Quotes a string as one POSIX shell word. */
export function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** Copies a substring so it does not keep the (possibly huge) parent string alive in V8. */
export function detach(s: string): string {
  return Buffer.from(s, "utf8").toString("utf8");
}

/* Cuts to the last n UTF-16 units without leaving a lone low surrogate at the start. */
function tail(s: string, n: number): string {
  const out = s.slice(-n);
  const c = out.charCodeAt(0);
  return c >= 0xdc00 && c <= 0xdfff ? out.slice(1) : out;
}

/** Accumulates stream chunks as UTF-8 without splitting multibyte characters, keeping only the last `cap` chars. */
export class OutputTail {
  private decoder = new StringDecoder("utf8");
  private text = "";
  private trimmed = false;
  total = 0;
  constructor(private cap: number) {}
  push(chunk: Buffer): void {
    this.total += chunk.length;
    this.text += this.decoder.write(chunk);
    if (this.text.length > this.cap * 2) {
      this.text = detach(tail(this.text, this.cap));
      this.trimmed = true;
    }
  }
  finish(): void {
    this.text += this.decoder.end();
  }
  toString(): string {
    if (this.text.length > this.cap) return "...[trimmed]..." + tail(this.text, this.cap);
    return this.trimmed ? "...[trimmed]..." + this.text : this.text;
  }
}

export function generateTempId(): string {
  return `${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

export function formatPermissions(mode: number): string {
  const perms = ["---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"];
  const owner = perms[(mode >> 6) & 7];
  const group = perms[(mode >> 3) & 7];
  const other = perms[mode & 7];
  return `${owner}${group}${other}`;
}

export function formatLogs(logs: LogEntry[], limit?: number): string {
  const logsToShow = limit ? logs.slice(-limit) : logs;
  return logsToShow
    .map((log) => {
      const time = log.timestamp.toISOString().replace("T", " ").substring(0, 19);
      const typeEmoji = {
        command: "⚡",
        output: "📤",
        error: "❌",
        info: "ℹ️",
        warning: "⚠️",
      }[log.type];
      return `[${time}] ${typeEmoji} ${log.type.toUpperCase()}: ${log.content}`;
    })
    .join("\n");
}
