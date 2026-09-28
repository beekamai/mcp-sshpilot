import type { Client, ConnectConfig, SFTPWrapper } from "ssh2";
import type { OutputTail } from "./utils.js";

export type ProxyType = "socks4" | "socks5" | "http" | "https";

export interface ProxyConfig {
  type: ProxyType;
  host: string;
  port: number;
  username?: string;
  password?: string;
}

export interface ServerProfile {
  name: string;
  host: string;
  port?: number;
  username: string;
  password?: string;
  privateKeyPath?: string;
  passphrase?: string;
  description?: string;
  /* Per-server proxy. null = force direct connection, overriding the global proxy. */
  proxy?: ProxyConfig | null;
}

export interface ServersConfig {
  proxy?: ProxyConfig;
  servers: ServerProfile[];
}

export interface LogEntry {
  timestamp: Date;
  type: "command" | "output" | "error" | "info" | "warning";
  content: string;
}

export interface SSHSession {
  client: Client;
  config: ConnectConfig;
  connected: boolean;
  logs: LogEntry[];
  startTime: Date;
  proxyUsed?: ProxyConfig;
  /** Random per connection; confirmations are bound to it so they cannot fire on another server. */
  id: string;
  /** user@host:port [via proxy], shown when a confirmation is refused. */
  target: string;
  /* One SFTP channel per session: opening one per call exhausts sshd MaxSessions (default 10). */
  sftp?: Promise<SFTPWrapper>;
}

/** Parameters of the last successful connect, replayed by ensureConnected() after the session drops. */
export interface LastConnect {
  config: ConnectConfig;
  proxy?: ProxyConfig;
  label: string;
}

export interface PendingConfirmation {
  id: string;
  command: string;
  reason: string;
  createdAt: Date;
  sessionId: string;
  target: string;
  timeoutMs?: number;
  background?: boolean;
}

export interface PendingDeleteConfirmation {
  id: string;
  path: string;
  isDirectory: boolean;
  createdAt: Date;
  sessionId: string;
  target: string;
}

export interface TempFile {
  id: string;
  localPath: string;
  remotePath: string;
  serverHost: string;
  filename: string;
  size: number;
  isBinary: boolean;
  downloadedAt: Date;
}

export interface BackgroundJob {
  id: string;
  command: string;
  startedAt: Date;
  stdout: OutputTail;
  stderr: OutputTail;
  done: boolean;
  exitCode: number | null;
  stream: any;
}

export type ProxyOverride =
  | { mode: "config" }
  | { mode: "disabled" }
  | { mode: "force"; proxy: ProxyConfig };
