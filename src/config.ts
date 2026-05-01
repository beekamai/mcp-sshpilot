import { readFileSync, existsSync, writeFileSync, mkdirSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { homedir } from "os";
import type { ConnectConfig } from "ssh2";
import type { ServersConfig, ServerProfile, ProxyConfig } from "./types.js";
import { describeProxy, resolveProxyForProfile } from "./proxy.js";
import { DEFAULT_KEEPALIVE_MS, DEFAULT_READY_TIMEOUT_MS } from "./state.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/* Resolution order:
 *   1. MCP_SSHPILOT_CONFIG env var (explicit path)
 *   2. <project_root>/servers.json (legacy, used if it already exists)
 *   3. ~/.config/mcp-sshpilot/servers.json (default for new installs;
 *      on Windows resolves to %USERPROFILE%\.config\mcp-sshpilot\servers.json)
 */
function resolveConfigPath(): string {
  const envPath = process.env.MCP_SSHPILOT_CONFIG;
  if (envPath && envPath.trim().length > 0) {
    return expandHome(envPath.trim());
  }
  const legacy = join(__dirname, "..", "servers.json");
  if (existsSync(legacy)) return legacy;
  return join(homedir(), ".config", "mcp-sshpilot", "servers.json");
}

function expandHome(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/") || p.startsWith("~\\")) return join(homedir(), p.slice(2));
  return p;
}

export const SERVERS_CONFIG_PATH = resolveConfigPath();

export function loadServersConfig(): ServersConfig {
  try {
    if (!existsSync(SERVERS_CONFIG_PATH)) return { servers: [] };
    const parsed = JSON.parse(readFileSync(SERVERS_CONFIG_PATH, "utf-8")) as ServersConfig;
    if (!Array.isArray(parsed.servers)) parsed.servers = [];
    return parsed;
  } catch {
    return { servers: [] };
  }
}

/* Ensure the config file exists at startup. Creates parent dirs and writes
 * a stub `{ servers: [] }` so users see a clear file to edit (and CRUD tools
 * have somewhere to write). Idempotent: never overwrites an existing file. */
export function ensureServersConfigExists(): { created: boolean; path: string } {
  if (existsSync(SERVERS_CONFIG_PATH)) return { created: false, path: SERVERS_CONFIG_PATH };
  const dir = dirname(SERVERS_CONFIG_PATH);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(SERVERS_CONFIG_PATH, JSON.stringify({ servers: [] }, null, 2) + "\n", "utf-8");
  return { created: true, path: SERVERS_CONFIG_PATH };
}

export function saveServersConfig(cfg: ServersConfig): void {
  const dir = dirname(SERVERS_CONFIG_PATH);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(SERVERS_CONFIG_PATH, JSON.stringify(cfg, null, 2) + "\n", "utf-8");
}

export function getServerProfile(profileName: string): ServerProfile | null {
  const cfg = loadServersConfig();
  return (
    cfg.servers.find((s) => s.name.toLowerCase() === profileName.toLowerCase()) || null
  );
}

export function listProfiles(): {
  name: string;
  host: string;
  description?: string;
  proxy?: string;
}[] {
  const cfg = loadServersConfig();
  return cfg.servers.map((s) => ({
    name: s.name,
    host: `${s.host}:${s.port || 22}`,
    description: s.description,
    proxy: describeProxy(resolveProxyForProfile(s, cfg)),
  }));
}

export function profileToConnectConfig(profile: ServerProfile): ConnectConfig {
  let privateKey: string | undefined;
  if (profile.privateKeyPath) {
    try {
      const keyPath =
        profile.privateKeyPath.startsWith("/") || profile.privateKeyPath.includes(":")
          ? profile.privateKeyPath
          : join(__dirname, "..", profile.privateKeyPath);
      privateKey = readFileSync(keyPath, "utf-8");
    } catch {
      throw new Error(`Failed to read SSH key: ${profile.privateKeyPath}`);
    }
  }
  return {
    host: profile.host,
    port: profile.port || 22,
    username: profile.username,
    password: profile.password,
    privateKey,
    passphrase: profile.passphrase,
    keepaliveInterval: DEFAULT_KEEPALIVE_MS,
    keepaliveCountMax: 3,
    readyTimeout: DEFAULT_READY_TIMEOUT_MS,
  };
}

export type { ProxyConfig };
