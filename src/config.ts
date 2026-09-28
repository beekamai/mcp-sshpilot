import { readFileSync, existsSync, writeFileSync, mkdirSync, renameSync, unlinkSync, realpathSync } from "fs";
import { randomBytes } from "crypto";
import { fileURLToPath } from "url";
import { dirname, join, isAbsolute } from "path";
import { homedir } from "os";
import type { ConnectConfig } from "ssh2";
import type { ServersConfig, ServerProfile, ProxyConfig } from "./types.js";
import { describeProxy, resolveProxyForProfile } from "./proxy.js";
import { DEFAULT_KEEPALIVE_MS, DEFAULT_READY_TIMEOUT_MS } from "./state.js";
import { assertNotUnc } from "./utils.js";

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

/* A broken file must throw: returning an empty list here would let ssh_server_add overwrite every saved profile. */
export function loadServersConfig(): ServersConfig {
  if (!existsSync(SERVERS_CONFIG_PATH)) return { servers: [] };
  const raw = readFileSync(SERVERS_CONFIG_PATH, "utf-8");
  let parsed: ServersConfig;
  try {
    parsed = JSON.parse(raw) as ServersConfig;
  } catch (e) {
    /* Only the position: Node's JSON.parse message quotes the surrounding text, which may be a password. */
    const where = /position \d+(?: \(line \d+ column \d+\))?/.exec(e instanceof Error ? e.message : "")?.[0];
    throw new Error(`Servers config ${SERVERS_CONFIG_PATH} is not valid JSON${where ? ` (at ${where})` : ""}. Fix it by hand; it was left untouched.`);
  }
  if (!Array.isArray(parsed.servers)) parsed.servers = [];
  return parsed;
}

/* Ensure the config file exists at startup. Creates parent dirs and writes
 * a stub `{ servers: [] }` so users see a clear file to edit (and CRUD tools
 * have somewhere to write). Idempotent: never overwrites an existing file. */
export function ensureServersConfigExists(): { created: boolean; path: string } {
  if (existsSync(SERVERS_CONFIG_PATH)) return { created: false, path: SERVERS_CONFIG_PATH };
  const dir = dirname(SERVERS_CONFIG_PATH);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(SERVERS_CONFIG_PATH, JSON.stringify({ servers: [] }, null, 2) + "\n", { encoding: "utf-8", mode: 0o600 });
  return { created: true, path: SERVERS_CONFIG_PATH };
}

/* Temp file + rename so a crash mid-write cannot truncate the profiles. The temp name is random and
 * created exclusively (no pre-planted file), 0600 on POSIX because the file holds passwords. */
export function saveServersConfig(cfg: ServersConfig): void {
  const dir = dirname(SERVERS_CONFIG_PATH);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  /* Write through a symlinked config (dotfiles) instead of replacing the link with a plain file. */
  const target = existsSync(SERVERS_CONFIG_PATH) ? realpathSync(SERVERS_CONFIG_PATH) : SERVERS_CONFIG_PATH;
  const tmp = `${target}.${randomBytes(8).toString("hex")}.tmp`;
  try {
    writeFileSync(tmp, JSON.stringify(cfg, null, 2) + "\n", { encoding: "utf-8", mode: 0o600, flag: "wx" });
    renameSync(tmp, target);
  } catch (e) {
    try { unlinkSync(tmp); } catch { /* never created or already renamed */ }
    throw e;
  }
}

/* Relative key paths resolve against the config dir first, then the package dir (legacy layout). */
function resolveKeyPath(p: string): string {
  const expanded = expandHome(p);
  assertNotUnc(expanded, "key");
  if (isAbsolute(expanded)) return expanded;
  const nearConfig = join(dirname(SERVERS_CONFIG_PATH), expanded);
  return existsSync(nearConfig) ? nearConfig : join(__dirname, "..", expanded);
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
    const keyPath = resolveKeyPath(profile.privateKeyPath);
    try {
      privateKey = readFileSync(keyPath, "utf-8");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      throw new Error(`Failed to read SSH key ${profile.privateKeyPath} (${keyPath}): ${msg}`);
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
