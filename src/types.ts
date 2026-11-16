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
  privateKey?: string;
  passphrase?: string;
  /** Pinned host key, "SHA256:<base64>" as OpenSSH prints it. */
  hostKeySha256?: string;
  description?: string;
  /** Per-server proxy. null = force direct connection, overriding the global proxy. */
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
  /** Name of the connection the entry is about; undefined for session-wide entries. */
  conn?: string;
  connKey?: string;
}

export interface SSHSession {
  client: Client;
  /** Profile connections keep no password, key or passphrase here; reconnects re-read them from the store. */
  config: ConnectConfig;
  connected: boolean;
  startTime: Date;
  proxyUsed?: ProxyConfig;
  /** Random per connection; confirmations are bound to it so they cannot fire on another server. */
  id: string;
  /** user@host:port [via proxy], shown when a confirmation is refused. */
  target: string;
  /** One SFTP channel per session: opening one per call exhausts sshd MaxSessions (default 10). */
  sftp?: Promise<SFTPWrapper>;
  /** Host key seen in this handshake, "SHA256:<base64>". */
  hostKeySha256?: string;
  /** True when the key was checked against a profile's pin or was pinned into the profile by this connect. */
  hostKeyPinned?: boolean;
}

/** Parameters of the last successful connect, replayed by ensureConnected() after the session drops. */
export interface LastConnect {
  /** Without credentials when `profile` is set. */
  config: ConnectConfig;
  /** Saved profile the connection was made from; a reconnect re-reads its credentials by this name. */
  profile?: string;
  proxy?: ProxyConfig;
  label: string;
  hostKeySha256?: string;
  /** True when that key was checked against, or saved as, a profile's pin (ssh_status reports it). */
  hostKeyPinned?: boolean;
}

export interface PendingConfirmation {
  id: string;
  command: string;
  reason: string;
  createdAt: Date;
  /** Key of the connection it was issued on; it only ever runs there. */
  conn: string;
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
  conn: string;
  sessionId: string;
  target: string;
}

export interface TempFile {
  id: string;
  localPath: string;
  remotePath: string;
  serverHost: string;
  /** Name of the connection it was downloaded through; ssh_temp_upload without profile goes back there. */
  connection?: string;
  connectionKey?: string;
  /** user@host:port that connection pointed at; an upload back there is refused if the profile moved since. */
  endpoint?: string;
  filename: string;
  size: number;
  isBinary: boolean;
  downloadedAt: Date;
}

export interface BackgroundJob {
  id: string;
  /** Name and key of the connection the job runs on. */
  conn: string;
  connKey: string;
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
