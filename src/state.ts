import { detach } from "./utils.js";
import type {
  SSHSession,
  PendingConfirmation,
  PendingDeleteConfirmation,
  BackgroundJob,
  ProxyOverride,
  LogEntry,
  LastConnect,
} from "./types.js";

export const DEFAULT_EXEC_TIMEOUT_MS = 5 * 60 * 1000;
export const DEFAULT_KEEPALIVE_MS = 10_000;
export const DEFAULT_READY_TIMEOUT_MS = 30_000;

export const DEFAULT_SFTP_TIMEOUT_MS = 60_000;
export const DEFAULT_TRANSFER_TIMEOUT_MS = 10 * 60 * 1000;
export const CONFIRMATION_TTL_MS = 10 * 60 * 1000;

const MAX_LOG_ENTRIES = 500;
const MAX_LOG_ENTRY_CHARS = 4096;

export const state: { session: SSHSession | null; lastConnect: LastConnect | null } = {
  session: null,
  lastConnect: null,
};

export const pendingConfirmations: Map<string, PendingConfirmation> = new Map();
export const pendingDeleteConfirmations: Map<string, PendingDeleteConfirmation> = new Map();
export const backgroundJobs: Map<string, BackgroundJob> = new Map();

export let proxyOverride: ProxyOverride = { mode: "config" };
export function setProxyOverride(next: ProxyOverride): void {
  proxyOverride = next;
}
export function getProxyOverride(): ProxyOverride {
  return proxyOverride;
}

export function addLog(type: LogEntry["type"], content: string): void {
  if (!state.session) return;
  const logs = state.session.logs;
  const text = content.length > MAX_LOG_ENTRY_CHARS ? detach(content.slice(0, MAX_LOG_ENTRY_CHARS)) + "...[trimmed]" : content;
  logs.push({ timestamp: new Date(), type, content: text });
  if (logs.length > MAX_LOG_ENTRIES) logs.splice(0, logs.length - MAX_LOG_ENTRIES);
}
