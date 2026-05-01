import type { Client, ConnectConfig } from "ssh2";

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
}

export interface PendingConfirmation {
  id: string;
  command: string;
  reason: string;
  createdAt: Date;
}

export interface PendingDeleteConfirmation {
  id: string;
  path: string;
  isDirectory: boolean;
  createdAt: Date;
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
  stdout: string;
  stderr: string;
  done: boolean;
  exitCode: number | null;
  stream: any;
}

export type ProxyOverride =
  | { mode: "config" }
  | { mode: "disabled" }
  | { mode: "force"; proxy: ProxyConfig };
