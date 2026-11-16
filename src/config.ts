import { readFileSync, existsSync, writeFileSync, mkdirSync, renameSync, unlinkSync, realpathSync, openSync, closeSync, statSync } from "fs";
import { randomBytes } from "crypto";
import { fileURLToPath } from "url";
import { dirname, join, isAbsolute } from "path";
import { homedir } from "os";
import type { ConnectConfig } from "ssh2";
import type { ServersConfig, ServerProfile, ProxyConfig } from "./types.js";
import type { SessionCtx } from "./state.js";
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

export function expandHome(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/") || p.startsWith("~\\")) return join(homedir(), p.slice(2));
  return p;
}

export const SERVERS_CONFIG_PATH = resolveConfigPath();

/** Where server profiles live. Each session ctx holds one; handlers never touch the storage directly. */
export interface ProfileStore {
  /** Must throw on a broken store: an empty list here would let ssh_server_add overwrite every saved profile. */
  load(): ServersConfig;
  save(cfg: ServersConfig): void;
  /** Human-readable location for tool messages. Never contains secrets. */
  describe(): string;
  /** Private key contents for the profile, or undefined when it has none. */
  resolveKey(profile: ServerProfile): string | undefined;
  /** Drops in-memory secrets (e.g. a vault key) when the owning session ends. */
  dispose?(): void;
  /** load + mutate + save as one step against other writers; saves only when mutate changed something. */
  update?<T>(mutate: (cfg: ServersConfig) => T): T;
  /** Local files holding this store's secrets (the config itself, key files); ssh_upload refuses them. */
  protectedPaths?(): string[];
}

/** Read-modify-write of the profiles; atomic where the store supports it (the vault), load + save otherwise. */
export function updateStore<T>(store: ProfileStore, mutate: (cfg: ServersConfig) => T): T {
  if (store.update) return store.update(mutate);
  const cfg = store.load();
  const before = JSON.stringify(cfg);
  const result = mutate(cfg);
  if (JSON.stringify(cfg) !== before) store.save(cfg);
  return result;
}

const CONFIG_LOCK_WAIT_MS = 5_000;
/* A holder only loads, mutates in memory and saves (well under a second, rename retries included), so an older lock
 * was left by a process that died holding it. Age, not pid: Windows reuses pids. */
const CONFIG_LOCK_STALE_MS = 10_000;

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function isWindowsBusy(e: unknown): boolean {
  const code = (e as NodeJS.ErrnoException).code;
  return process.platform === "win32" && (code === "EPERM" || code === "EACCES" || code === "EBUSY");
}

/* Windows refuses to replace or delete a file that another process has open (a session's load() reading it) for the
 * moment the read takes. Readers take no lock, so retry briefly instead of failing. */
function retryWhileBusy(op: () => void): void {
  for (let attempt = 0; ; attempt++) {
    try {
      op();
      return;
    } catch (e) {
      if (!isWindowsBusy(e) || attempt >= 40) throw e;
      sleepSync(25);
    }
  }
}

/* Exclusive lock file next to the real config (through a symlink, like save). Holders are synchronous and never
 * nested, so a process never waits for itself. */
function withConfigLock<T>(configPath: string, fn: () => T): T {
  const lockPath = `${existsSync(configPath) ? realpathSync(configPath) : configPath}.lock`;
  const deadline = Date.now() + CONFIG_LOCK_WAIT_MS;
  for (;;) {
    try {
      closeSync(openSync(lockPath, "wx", 0o600));
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    }
    try {
      if (Date.now() - statSync(lockPath).mtimeMs > CONFIG_LOCK_STALE_MS) unlinkSync(lockPath);
    } catch {
      /* released or broken by another process meanwhile */
    }
    if (Date.now() > deadline) {
      throw new Error(`Servers config ${configPath} is locked by another session (${lockPath}); retry, or remove that file if it stays`);
    }
    sleepSync(25);
  }
  try {
    return fn();
  } finally {
    /* Left behind only if Windows keeps refusing; the next writer breaks it by age. */
    try { retryWhileBusy(() => unlinkSync(lockPath)); } catch { /* stale in CONFIG_LOCK_STALE_MS */ }
  }
}

/** Plain servers.json on the local disk (stdio mode). */
export class FileProfileStore implements ProfileStore {
  constructor(readonly path: string = SERVERS_CONFIG_PATH) {}

  load(): ServersConfig {
    if (!existsSync(this.path)) return { servers: [] };
    const raw = readFileSync(this.path, "utf-8");
    let parsed: ServersConfig;
    try {
      parsed = JSON.parse(raw) as ServersConfig;
    } catch (e) {
      /* Only the position: Node's JSON.parse message quotes the surrounding text, which may be a password. */
      const where = /position \d+(?: \(line \d+ column \d+\))?/.exec(e instanceof Error ? e.message : "")?.[0];
      throw new Error(`Servers config ${this.path} is not valid JSON${where ? ` (at ${where})` : ""}. Fix it by hand; it was left untouched.`);
    }
    if (!Array.isArray(parsed.servers)) parsed.servers = [];
    return parsed;
  }

  /** Creates parent dirs and a stub `{ servers: [] }` so users see a clear file to edit (and CRUD tools
   * have somewhere to write). Idempotent: never overwrites an existing file. */
  ensureExists(): { created: boolean; path: string } {
    if (existsSync(this.path)) return { created: false, path: this.path };
    const dir = dirname(this.path);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(this.path, JSON.stringify({ servers: [] }, null, 2) + "\n", { encoding: "utf-8", mode: 0o600 });
    return { created: true, path: this.path };
  }

  /** Temp file + rename so a crash mid-write cannot truncate the profiles. The temp name is random and
   * created exclusively (no pre-planted file), 0600 on POSIX because the file holds passwords. */
  save(cfg: ServersConfig): void {
    const dir = dirname(this.path);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    /* Write through a symlinked config (dotfiles) instead of replacing the link with a plain file. */
    const target = existsSync(this.path) ? realpathSync(this.path) : this.path;
    const tmp = `${target}.${randomBytes(8).toString("hex")}.tmp`;
    try {
      writeFileSync(tmp, JSON.stringify(cfg, null, 2) + "\n", { encoding: "utf-8", mode: 0o600, flag: "wx" });
      retryWhileBusy(() => renameSync(tmp, target));
    } catch (e) {
      try { unlinkSync(tmp); } catch { /* never created or already renamed */ }
      throw e;
    }
  }

  /** Several stdio processes (one per client session) share this file and every first connect writes a pin: re-read
   * under the lock so one process never saves a copy that predates another's write. */
  update<T>(mutate: (cfg: ServersConfig) => T): T {
    return withConfigLock(this.path, () => {
      const cfg = this.load();
      const before = JSON.stringify(cfg);
      const result = mutate(cfg);
      if (JSON.stringify(cfg) !== before) this.save(cfg);
      return result;
    });
  }

  describe(): string {
    return this.path;
  }

  protectedPaths(): string[] {
    const out = [this.path];
    try {
      for (const p of this.load().servers) {
        if (!p.privateKeyPath) continue;
        try { out.push(this.resolveKeyPath(p.privateKeyPath)); } catch { /* a UNC path is refused on use anyway */ }
      }
    } catch { /* a broken config still protects itself */ }
    return out;
  }

  resolveKey(profile: ServerProfile): string | undefined {
    if (!profile.privateKeyPath) return profile.privateKey;
    const keyPath = this.resolveKeyPath(profile.privateKeyPath);
    try {
      return readFileSync(keyPath, "utf-8");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      throw new Error(`Failed to read SSH key ${profile.privateKeyPath} (${keyPath}): ${msg}`);
    }
  }

  /* Relative key paths resolve against the config dir first, then the package dir (legacy layout). */
  private resolveKeyPath(p: string): string {
    const expanded = expandHome(p);
    assertNotUnc(expanded, "key");
    if (isAbsolute(expanded)) return expanded;
    const nearConfig = join(dirname(this.path), expanded);
    return existsSync(nearConfig) ? nearConfig : join(__dirname, "..", expanded);
  }
}

export function getServerProfile(cfg: ServersConfig, profileName: string): ServerProfile | null {
  return (
    cfg.servers.find((s) => s.name.toLowerCase() === profileName.toLowerCase()) || null
  );
}

export function listProfiles(ctx: SessionCtx, cfg: ServersConfig = ctx.store.load()): {
  name: string;
  host: string;
  description?: string;
  proxy?: string;
}[] {
  return cfg.servers.map((s) => ({
    name: s.name,
    host: `${s.host}:${s.port || 22}`,
    description: s.description,
    proxy: describeProxy(resolveProxyForProfile(ctx, s, cfg)),
  }));
}

export function profileToConnectConfig(store: ProfileStore, profile: ServerProfile): ConnectConfig {
  return {
    host: profile.host,
    port: profile.port || 22,
    username: profile.username,
    password: profile.password,
    privateKey: store.resolveKey(profile),
    passphrase: profile.passphrase,
    keepaliveInterval: DEFAULT_KEEPALIVE_MS,
    keepaliveCountMax: 3,
    readyTimeout: DEFAULT_READY_TIMEOUT_MS,
  };
}

export type { ProxyConfig };
