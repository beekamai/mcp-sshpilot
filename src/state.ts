import type {
  SSHSession,
  PendingConfirmation,
  PendingDeleteConfirmation,
  BackgroundJob,
  ProxyOverride,
  LogEntry,
} from "./types.js";

export const DEFAULT_EXEC_TIMEOUT_MS = 5 * 60 * 1000;
export const DEFAULT_KEEPALIVE_MS = 10_000;
export const DEFAULT_READY_TIMEOUT_MS = 30_000;

export const state: { session: SSHSession | null } = { session: null };

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
  if (state.session) {
    state.session.logs.push({ timestamp: new Date(), type, content });
  }
}
