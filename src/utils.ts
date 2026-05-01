import type { LogEntry } from "./types.js";

export function generateId(): string {
  return Math.random().toString(36).substring(2, 10);
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
