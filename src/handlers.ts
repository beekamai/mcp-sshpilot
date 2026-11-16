import ssh2 from "ssh2";
import type { ConnectConfig } from "ssh2";
import type { ServerProfile, ServersConfig, ProxyConfig } from "./types.js";
import { isToolAvailable } from "./tools.js";
import {
  CONFIRMATION_TTL_MS,
  DEFAULT_EXEC_TIMEOUT_MS,
  DEFAULT_SFTP_TIMEOUT_MS,
  DEFAULT_TRANSFER_TIMEOUT_MS,
  addLog,
  connKey,
} from "./state.js";
import type { Conn, SessionCtx } from "./state.js";
import { generateId, formatBytes, formatLogs, plainText } from "./utils.js";
import { checkDangerousCommand } from "./danger.js";
import { getServerProfile, listProfiles, profileToConnectConfig, updateStore } from "./config.js";
import { describeProxy, validateProxy, resolveProxyForProfile } from "./proxy.js";
import {
  sshConnect,
  HostKeyMismatchError,
  normalizeHostKeyFingerprint,
  ensureConnected,
  withDeadline,
  clampTimeout,
  connectionNames,
  findConn,
  keysOfName,
  rawConnName,
  scanHostKey,
  REMOTE_MAX_EXEC_TIMEOUT_MS,
  sshDisconnect,
  sshExecute,
  sshExecuteBackground,
  readBackgroundJob,
  killBackgroundJob,
  listBackgroundJobs,
} from "./ssh-core.js";
import {
  sshUploadFile,
  sshReadFile,
  sshListDir,
  sshDownloadFile,
  sshUploadFromTemp,
  sshFileInfo,
  sshMkdir,
  sshRename,
  sshChmod,
  sshDelete,
  sshCopy,
  sshUpload,
  ReadBudget,
  inlineBusyMessage,
} from "./ssh-fs.js";
import {
  listTempFiles,
  getTempFile,
  readTempFileContent,
  updateTempFile,
  deleteTempFile,
  cleanupAllTempFiles,
  REMOTE_INLINE_MAX_BYTES,
} from "./temp.js";

/* Tools that need no connection, or are bound to one by an id (background jobs). */
const SESSION_FREE_TOOLS = new Set([
  "ssh_connect",
  "ssh_connect_profile",
  "ssh_disconnect",
  "ssh_status",
  "ssh_list_profiles",
  "ssh_server_add",
  "ssh_server_remove",
  "ssh_server_update",
  "ssh_proxy_status",
  "ssh_proxy_set",
  "ssh_proxy_enable",
  "ssh_proxy_disable",
  "ssh_pending_confirmations",
  "ssh_read_background",
  "ssh_kill_background",
  "ssh_list_background",
  "ssh_temp_list",
  "ssh_temp_read",
  "ssh_temp_write",
  "ssh_temp_delete",
  "ssh_temp_cleanup",
  "ssh_temp_path",
  "ssh_get_logs",
  "ssh_pin_host_keys",
]);

const TRANSFER_TOOLS = new Set(["ssh_upload", "ssh_download_file", "ssh_temp_upload", "ssh_copy"]);
const CONFIRM_TOOLS = new Set(["ssh_execute_dangerous", "ssh_delete_confirm"]);

/* DNS, a proxy handshake (up to 30 s) and the SSH ready timeout (30 s), with slack. */
const CONNECT_DEADLINE_MS = 75_000;

/* Pending confirmations hold the full command until confirmed; bounded so a loop of dangerous calls cannot pile up. */
const MAX_PENDING_CONFIRMATIONS = 16;
/* Ids of confirmations dropped by that cap, remembered so confirming one does not look like an expiry. */
const MAX_DROPPED_CONFIRMATION_IDS = 256;
const REMOTE_MAX_HELD_COMMAND_CHARS = 64 * 1024;
const SCAN_CONCURRENCY = 4;

type ToolResult = { content: { type: "text"; text: string }[]; isError?: boolean };

/** One call's binding: the connection it registered, joined or resolved (its deadlines act on that object, never on
 * a later connection of the same name), and the audit target when the call was refused before binding one. */
interface CallState {
  bound?: Conn;
  audit?: string;
}

/* Endpoint each call resolved to, keyed by its arguments object (the hook passes the same one), so an audit line
 * written after the call still names it although the call consumed its confirmation. */
const callTargets = new WeakMap<object, string>();

/* Key material of ssh_server_add/update. Remote mode takes the key inline (the vault encrypts it) and refuses
 * paths into the host's filesystem; stdio mode keeps servers.json free of key contents. The key is never echoed. */
function applyKeyArgs(ctx: SessionCtx, profile: ServerProfile, a: any): void {
  if (ctx.mode === "remote") {
    if (a.privateKeyPath !== undefined) {
      throw new Error("privateKeyPath is not accepted in remote mode; pass the key contents as privateKey");
    }
    if (typeof a.privateKey === "string") {
      const parsed = ssh2.utils.parseKey(a.privateKey, typeof a.passphrase === "string" ? a.passphrase : profile.passphrase);
      if (parsed instanceof Error || (Array.isArray(parsed) ? parsed.length === 0 : !parsed.isPrivateKey())) {
        throw new Error("privateKey is not a usable private key (wrong format or passphrase)");
      }
      profile.privateKey = a.privateKey;
      delete profile.privateKeyPath;
    }
    return;
  }
  if (typeof a.privateKeyPath === "string") profile.privateKeyPath = a.privateKeyPath;
}

/* A confirmation is only valid in the connection it was issued in (a reconnect or another server voids it) and only for a limited time. */
function confirmationProblem(conn: Conn, p: { sessionId: string; target: string; createdAt: Date }): string | null {
  if (Date.now() - p.createdAt.getTime() > CONFIRMATION_TTL_MS) return "expired";
  if (conn.session?.id !== p.sessionId) {
    return `issued for ${p.target} in an earlier connection; current: ${conn.session?.target ?? "not connected"}`;
  }
  return null;
}

function pruneExpiredConfirmations(ctx: SessionCtx): void {
  const now = Date.now();
  for (const map of [ctx.pendingConfirmations, ctx.pendingDeleteConfirmations] as Map<string, { createdAt: Date }>[]) {
    for (const [id, p] of map) if (now - p.createdAt.getTime() > CONFIRMATION_TTL_MS) map.delete(id);
  }
}

/* Map order is insertion order: beyond the cap the oldest pending confirmation is dropped, and remembered as dropped. */
function holdConfirmation<T extends { createdAt: Date; conn: string }>(ctx: SessionCtx, map: Map<string, T>, id: string, entry: T): void {
  pruneExpiredConfirmations(ctx);
  for (const [oldest, dropped] of map) {
    if (map.size < MAX_PENDING_CONFIRMATIONS) break;
    map.delete(oldest);
    ctx.droppedConfirmations.add(oldest);
    for (const old of ctx.droppedConfirmations) {
      if (ctx.droppedConfirmations.size <= MAX_DROPPED_CONFIRMATION_IDS) break;
      ctx.droppedConfirmations.delete(old);
    }
    addLog(ctx.connections.get(dropped.conn) ?? ctx, "warning", `Pending confirmation ${oldest} dropped: more than ${MAX_PENDING_CONFIRMATIONS} were pending`);
  }
  map.set(id, entry);
}

function confirmationGone(ctx: SessionCtx, id: string, rerun: string): ToolResult {
  if (ctx.droppedConfirmations.has(id)) {
    return {
      content: [{
        type: "text",
        text:
          `❌ Confirmation "${id}" was dropped: more than ${MAX_PENDING_CONFIRMATIONS} confirmations were pending in this session ` +
          `and it was the oldest. Nothing was executed. Re-run ${rerun} to get a new one.`,
      }],
      isError: true,
    };
  }
  return { content: [{ type: "text", text: `❌ Confirmation "${id}" not found or expired` }] };
}

/* What decides where a profile's credentials go: its endpoint and its own proxy setting. */
function routeOf(p: ServerProfile): string {
  return JSON.stringify([p.username, p.host, p.port || 22, p.proxy === undefined ? "inherit" : p.proxy]);
}

/* Remote mode: a stored password reaches only a server whose host key matches the profile's pin. A profile that is
 * not pinned yet would pin, and receive the password, at whatever answers on a route the model just changed. */
const PASSWORD_DROPPED_NOTE =
  "Stored password removed: the profile has no pinned host key yet and its route changed, so the password would go to " +
  "whatever answers there. Pass password again if this route is intended.";

function dropUnpinnedPassword(p: ServerProfile): boolean {
  if (p.hostKeySha256 || p.password === undefined) return false;
  delete p.password;
  return true;
}

/* Remote mode: changing the global proxy reroutes every profile that inherits it. */
function dropInheritingPasswords(ctx: SessionCtx, cfg: ServersConfig, next: ProxyConfig | undefined): string {
  if (ctx.mode !== "remote" || JSON.stringify(cfg.proxy ?? null) === JSON.stringify(next ?? null)) return "";
  const names = cfg.servers.filter((s) => s.proxy === undefined && dropUnpinnedPassword(s)).map((s) => s.name);
  return names.length > 0
    ? `\nStored password removed from ${names.join(", ")}: not pinned yet and their route changed. Pass password again with ssh_server_update if intended.`
    : "";
}

/* Trust on first use: saves the key of a successful handshake into the profile. Re-reads the store so a pin written meanwhile by another session wins. */
function pinOnFirstUse(conn: Conn, profile: ServerProfile, seen: string | undefined): string {
  const ctx = conn.ctx;
  if (!seen || !conn.session) return "⚠️ Host key was not observed; profile not pinned.";
  const endpoint = (s: ServerProfile) => `${s.username}@${s.host}:${s.port || 22}`;
  let outcome: "changed" | "matches" | "pinned";
  try {
    /* Check and pin under one store lock: a pin the owner sets meanwhile must win, not be overwritten. */
    outcome = updateStore(ctx.store, (cfg): "changed" | "matches" | "pinned" => {
      const fresh = cfg.servers.find((s) => s.name.toLowerCase() === profile.name.toLowerCase());
      if (!fresh || endpoint(fresh) !== endpoint(profile)) return "changed";
      if (fresh.hostKeySha256) {
        const pinned = normalizeHostKeyFingerprint(fresh.hostKeySha256);
        if (pinned !== seen) throw new HostKeyMismatchError(endpoint(profile), pinned, seen, ctx.mode, true, true);
        return "matches";
      }
      fresh.hostKeySha256 = seen;
      return "pinned";
    });
  } catch (err) {
    if (err instanceof HostKeyMismatchError) {
      sshDisconnect(conn);
      throw err;
    }
    return `⚠️ Connected, but the host key pin could not be saved (${err instanceof Error ? err.message : String(err)}); the profile stays unpinned.`;
  }
  if (outcome === "changed") return "⚠️ Profile changed while connecting; host key not pinned.";
  markPinned(conn);
  if (outcome === "matches") return `🔐 Host key ${seen} matches the pin.`;
  addLog(conn, "info", `Pinned host key ${seen} for profile ${profile.name}`);
  return (
    `🔐 First connection with this profile: pinned host key ${seen} (trust on first use). ` +
    `Check it against the server (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub); any other key will now be refused.`
  );
}

function maxExecTimeout(ctx: SessionCtx): number | undefined {
  return ctx.mode === "remote" ? REMOTE_MAX_EXEC_TIMEOUT_MS : undefined;
}

function markPinned(conn: Conn): void {
  if (conn.session) conn.session.hostKeyPinned = true;
  if (conn.lastConnect) conn.lastConnect.hostKeyPinned = true;
}

/* The agent reads this and must stop: it cannot verify a key out of band, and whoever answers an unpinned first
 * connection would receive the profile's credentials. */
function tofuRefused(name: string): string {
  return (
    `Profile "${name}" has no pinned host key, and this server does not trust a host key on first use: whoever ` +
    `answered this first connection would receive the profile's credentials. Nothing was sent. Stop and tell the user. ` +
    `The owner pins the key out of band, on a machine holding a vault unlock key: ` +
    `${PIN_COMMAND}, with a fingerprint checked on the server itself (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub) or ` +
    `obtained with ssh_pin_host_keys in a local stdio session; or starts the server with \`serve --allow-tofu\`.`
  );
}

const PIN_COMMAND = "`mcp-sshpilot vault pin-host-key <profile> <SHA256:...>`";

/** Connects a saved profile, with the pin checks of ssh_connect_profile. Shared by it and by tools called with a
 * `profile` that is not connected yet. */
async function connectProfile(ctx: SessionCtx, profile: ServerProfile, cfg: ServersConfig, st: CallState): Promise<{ conn: Conn; note: string }> {
  const proxy = resolveProxyForProfile(ctx, profile, cfg);
  if (ctx.mode === "remote" && !profile.hostKeySha256) {
    if (!ctx.allowTofu) throw new Error(tofuRefused(profile.name));
    /* The first connection pins whatever answers, so it takes the vault's route: an override is fine only where it
     * changes nothing (ssh_proxy_disable on a profile that goes direct anyway). */
    const stored = profile.proxy === null ? undefined : profile.proxy ?? cfg.proxy;
    if (JSON.stringify(proxy ?? null) !== JSON.stringify(stored ?? null)) {
      throw new Error(
        `Profile "${profile.name}" has no pinned host key yet. Its first connection must take the route stored in the vault, ` +
          `not this session's proxy override: run ssh_proxy_enable first, or have the owner pin it (${PIN_COMMAND}).`
      );
    }
  }
  const config = profileToConnectConfig(ctx.store, profile);
  const { conn, message, joined } = await sshConnect(ctx, config, proxy, {
    expectedHostKey: profile.hostKeySha256,
    pinned: !!profile.hostKeySha256,
    profile: profile.name,
    bind: (c) => { st.bound = c; },
  });
  if (joined) return { conn, note: message };
  const seen = conn.session?.hostKeySha256;
  const keyNote = profile.hostKeySha256 ? `🔐 Host key ${seen} matches the pin.` : pinOnFirstUse(conn, profile, seen);
  return {
    conn,
    note: `${message}\n(profile: ${profile.name}${profile.description ? ` — ${profile.description}` : ""})\n${keyNote}`,
  };
}

/* Absent (or null) means omitted; anything else that is not a name is refused rather than read as omitted, which
 * would run the call on the only open connection. */
function profileArg(args: any): string | undefined {
  const p = args?.profile;
  if (p === undefined || p === null) return undefined;
  if (typeof p !== "string" || p.trim().length === 0) {
    throw new Error("profile must be a non-empty string: a saved profile or open connection name. Nothing was executed.");
  }
  return p.trim();
}

/* An open connection by name, else a saved profile of that name, connected now. */
async function connectionFor(ctx: SessionCtx, name: string, st: CallState, origin = "", endpoint?: string): Promise<{ conn: Conn; note?: string }> {
  const saved = () => {
    const cfg = ctx.store.load();
    return { cfg, profile: getServerProfile(cfg, name) };
  };
  const moved = (now: string | undefined) => {
    if (endpoint !== undefined && now !== endpoint) {
      throw new Error(`"${name}" now points at ${now ?? "nothing"}, not ${endpoint}${origin}. Nothing was uploaded.`);
    }
  };
  const conn = findConn(ctx, name);
  if (conn) {
    const p = endpoint === undefined ? null : endpointOfConn(conn) === undefined ? saved().profile : null;
    moved(endpointOfConn(conn) ?? (p ? endpointOfProfile(p) : undefined));
    st.bound = conn;
    return { conn };
  }
  const { cfg, profile } = saved();
  if (!profile) {
    throw new Error(`No open connection or saved profile named "${name}"${origin}. Open connections: ${connectionNames(ctx)}.`);
  }
  moved(endpointOfProfile(profile));
  return connectProfile(ctx, profile, cfg, st);
}

function endpointOfProfile(p: ServerProfile): string {
  return `${p.username}@${p.host}:${p.port || 22}`;
}

/** Which connection a call acts on. Never falls back to another connection than the one named or bound. */
async function resolveTarget(ctx: SessionCtx, name: string, args: any, st: CallState): Promise<{ conn: Conn; note?: string } | undefined> {
  const requested = profileArg(args);
  if (CONFIRM_TOOLS.has(name)) {
    const map: Map<string, { conn: string; target: string }> =
      name === "ssh_execute_dangerous" ? ctx.pendingConfirmations : ctx.pendingDeleteConfirmations;
    const id = args?.confirmation_id as string;
    const pending = map.get(id);
    /* Unknown ids and cancellations are answered by the handler and need no connection. */
    if (!pending || args?.confirm !== true) return undefined;
    /* Audited against the server it was issued for, whatever else is open. */
    st.audit = pending.target.split(" via ")[0];
    const conn = ctx.connections.get(pending.conn);
    if (!conn) {
      map.delete(id);
      throw new Error(`Confirmation "${id}" refused: the connection it was issued on (${pending.target}) is closed. Nothing was executed.`);
    }
    if (requested !== undefined && findConn(ctx, requested) !== conn) {
      throw new Error(
        `Confirmation "${id}" was issued for ${pending.target}, not for "${requested}", and only runs there. Nothing was executed; ` +
          `confirm it without profile (or with the connection it was issued on).`
      );
    }
    st.audit = undefined;
    st.bound = conn;
    return { conn };
  }
  if (name === "ssh_temp_upload" && requested === undefined) {
    const tf = getTempFile(ctx, args?.temp_id as string);
    if (tf?.connection !== undefined) {
      return connectionFor(ctx, tf.connection, st, ` (temp file ${tf.id} was downloaded from it; pass profile to upload it elsewhere)`, tf.endpoint);
    }
  }
  if (requested !== undefined) return connectionFor(ctx, requested, st);
  const all = [...ctx.connections.values()];
  if (all.length === 0) throw new Error("No active SSH connection");
  if (all.length > 1) {
    throw new Error(`${all.length} connections are open (${connectionNames(ctx)}); pass profile to choose one. Nothing was executed.`);
  }
  st.bound = all[0];
  return { conn: all[0] };
}

/* Where the connection last dialed, else where it is connected. */
function endpointOfConn(conn: Conn): string | undefined {
  if (conn.endpoint) return conn.endpoint;
  const cfg = conn.session?.config ?? conn.lastConnect?.config;
  return cfg?.host ? `${cfg.username}@${cfg.host}:${Number(cfg.port) || 22}` : undefined;
}

/** user@host:port of the connection a call would use (the one it used, once it ran), or "-". For audit lines:
 * never includes credentials. */
export function describeCallTarget(ctx: SessionCtx, args: unknown, name?: string): string {
  try {
    const a = (args ?? {}) as any;
    const clean = (s: string | undefined) => (s ? plainText(s, 300) || "-" : "-");
    const resolved = args && typeof args === "object" ? callTargets.get(args) : undefined;
    if (resolved !== undefined) return clean(resolved);
    if (name !== undefined && SESSION_FREE_TOOLS.has(name) && name !== "ssh_connect" && name !== "ssh_connect_profile") return "-";
    if (typeof a.confirmation_id === "string") {
      const p = ctx.pendingConfirmations.get(a.confirmation_id) ?? ctx.pendingDeleteConfirmations.get(a.confirmation_id);
      return p ? clean(p.target.split(" via ")[0]) : "-";
    }
    if (typeof a.host === "string" && typeof a.username === "string") {
      return clean(rawConnName({ host: a.host, port: Number(a.port) || 22, username: a.username }));
    }
    const named = profileArg(a) ?? (typeof a.profile_name === "string" ? a.profile_name : undefined);
    if (named !== undefined) {
      const conn = findConn(ctx, named);
      if (conn) return clean(endpointOfConn(conn));
      const p = getServerProfile(ctx.store.load(), named);
      return p ? clean(`${p.username}@${p.host}:${p.port || 22}`) : "-";
    }
    const all = [...ctx.connections.values()];
    return all.length === 1 ? clean(endpointOfConn(all[0])) : "-";
  } catch {
    return "-";
  }
}

async function startBackground(conn: Conn, command: string): Promise<ToolResult> {
  const { id } = await sshExecuteBackground(conn, command);
  return {
    content: [{
      type: "text",
      text:
        `🟢 Background job started\njob_id: ${id}\nconnection: ${conn.name}\ncommand: ${command}\n\n` +
        `Read:  ssh_read_background({job_id:"${id}"})\n` +
        `Stop:  ssh_kill_background({job_id:"${id}"})`,
    }],
  };
}

/* Runs fn over items with at most `limit` in flight; results keep the items' order. */
async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

export async function handleToolCall(ctx: SessionCtx, name: string, args: any): Promise<ToolResult> {
  /* Remote mode: inline content this call buffers stays reserved until its result has been serialized. */
  const hold = new ReadBudget(ctx, "inline");
  let target: Conn | undefined;
  const st: CallState = {};
  try {
    if (!isToolAvailable(ctx.mode, name, ctx.scoped)) {
      const where =
        ctx.scoped && isToolAvailable(ctx.mode, name)
          ? "to a connector grant (its profiles are read-only)"
          : ctx.mode === "remote" ? "in remote mode" : "in stdio mode";
      return { content: [{ type: "text", text: `❌ ${name} is not available ${where}` }], isError: true };
    }
    const notes: string[] = [];
    const deadlineConn = () => st.bound;
    if (!SESSION_FREE_TOOLS.has(name)) {
      /* Connecting and reconnecting run under their own deadline: a stalled handshake must not hang the call. */
      await withDeadline(deadlineConn, (async () => {
        const resolved = await resolveTarget(ctx, name, args, st);
        target = resolved?.conn;
        if (resolved?.note) notes.push(resolved.note);
        if (target) {
          const note = await ensureConnected(target);
          if (note) notes.push(note);
        }
      })(), CONNECT_DEADLINE_MS, `${name}: connecting`);
    }
    const requested = name === "ssh_execute_dangerous" ? ctx.pendingConfirmations.get(args?.confirmation_id)?.timeoutMs : args?.timeout_ms;
    const execLimit = (clampTimeout(requested, maxExecTimeout(ctx)) ?? DEFAULT_EXEC_TIMEOUT_MS) + 5_000;
    const deadline =
      name === "ssh_execute" || name === "ssh_execute_dangerous" ? execLimit
      : name === "ssh_connect" || name === "ssh_connect_profile" ? CONNECT_DEADLINE_MS
      : TRANSFER_TOOLS.has(name) || name === "ssh_pin_host_keys" ? DEFAULT_TRANSFER_TIMEOUT_MS
      : DEFAULT_SFTP_TIMEOUT_MS;
    const result = await withDeadline(deadlineConn, dispatch(ctx, name, args, hold, target, st), deadline, name);
    if (notes.length > 0 && result.content.length > 0 && result.content[0].type === "text") {
      result.content[0].text = `${notes.join("\n")}\n${result.content[0].text}`;
    }
    return result;
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    addLog(target ?? ctx, "error", msg);
    return { content: [{ type: "text", text: `❌ Error: ${msg}` }], isError: true };
  } finally {
    const endpoint = st.audit ?? (st.bound && endpointOfConn(st.bound));
    if (endpoint && args && typeof args === "object") callTargets.set(args, endpoint);
    /* The SDK serializes the result in the microtasks right after this returns; a macrotask runs after that. */
    setImmediate(() => hold.release());
  }
}

async function dispatch(ctx: SessionCtx, name: string, args: any, hold: ReadBudget, target: Conn | undefined, st: CallState): Promise<ToolResult> {
  const conn = (): Conn => {
    if (!target) throw new Error("No active SSH connection");
    return target;
  };
  try {
    switch (name) {
      case "ssh_connect": {
        const config: ConnectConfig = {
          host: args?.host as string,
          port: (args?.port as number) || 22,
          username: args?.username as string,
          password: args?.password as string | undefined,
          privateKey: args?.privateKey as string | undefined,
          passphrase: args?.passphrase as string | undefined,
        };
        let proxy: ProxyConfig | undefined;
        const override = ctx.proxyOverride;
        if (args?.proxy) proxy = validateProxy(args.proxy);
        else if (override.mode === "force") proxy = override.proxy;
        else if (override.mode === "config") proxy = ctx.store.load().proxy;
        const { conn: c, message } = await sshConnect(ctx, config, proxy, { bind: (b) => { st.bound = b; } });
        return { content: [{ type: "text", text: `${message}\n(connection: ${c.name}; pass it as profile while other connections are open)` }] };
      }

      case "ssh_connect_profile": {
        const profileName = args?.profile_name as string;
        const cfg = ctx.store.load();
        const profile = getServerProfile(cfg, String(profileName));
        if (!profile) {
          const profiles = listProfiles(ctx, cfg);
          const available =
            profiles.length > 0
              ? `\n\nAvailable: ${profiles.map((p) => p.name).join(", ")}`
              : "\n\nservers.json is empty. Use ssh_server_add or copy servers.example.json.";
          return {
            content: [{ type: "text", text: `❌ Profile "${profileName}" not found.${available}` }],
          };
        }
        const { note } = await connectProfile(ctx, profile, cfg, st);
        return { content: [{ type: "text", text: note }] };
      }

      case "ssh_list_profiles": {
        const profiles = listProfiles(ctx);
        if (profiles.length === 0) {
          return {
            content: [{
              type: "text",
              text: `📋 No profiles.\nAdd one via ssh_server_add or create ${ctx.store.describe()}`,
            }],
          };
        }
        const list = profiles
          .map((p) => {
            const desc = p.description ? ` (${p.description})` : "";
            const px = p.proxy ? `  [proxy: ${p.proxy}]` : "";
            const live = ctx.connections.has(connKey(p.name)) ? "  [connected]" : "";
            return `• ${p.name} → ${p.host}${desc}${px}${live}`;
          })
          .join("\n");
        return { content: [{ type: "text", text: `📋 Profiles:\n\n${list}` }] };
      }

      case "ssh_server_add": return updateStore(ctx.store, (cfg) => {
        const a = args || {};
        const newName = String(a.name ?? "");
        if (newName.trim().length === 0) throw new Error("name must be a non-empty string");
        if (cfg.servers.some((s) => s.name.toLowerCase() === newName.toLowerCase())) {
          return { content: [{ type: "text", text: `❌ Profile "${newName}" already exists. Use ssh_server_update.` }] };
        }
        const profile: ServerProfile = {
          name: newName,
          host: String(a.host),
          username: String(a.username),
        };
        if (typeof a.port === "number") profile.port = a.port;
        if (typeof a.password === "string") profile.password = a.password;
        applyKeyArgs(ctx, profile, a);
        if (typeof a.passphrase === "string") profile.passphrase = a.passphrase;
        if (typeof a.description === "string") profile.description = a.description;
        if (a.proxy === null) profile.proxy = null;
        else if (a.proxy && typeof a.proxy === "object") profile.proxy = validateProxy(a.proxy);
        cfg.servers.push(profile);
        return {
          content: [{
            type: "text",
            text: `✅ Profile "${newName}" added (${profile.host}:${profile.port || 22}).`,
          }],
        };
      });

      case "ssh_server_update": return updateStore(ctx.store, (cfg) => {
        const a = args || {};
        if (a.reset_host_key === true && ctx.mode === "remote") {
          throw new Error(
            "reset_host_key is not available in remote mode: an agent cannot verify a host key. The owner re-pins out of band " +
            "with `mcp-sshpilot vault pin-host-key <profile> <SHA256:...>`."
          );
        }
        const targetName = String(a.name);
        const idx = cfg.servers.findIndex((s) => s.name.toLowerCase() === targetName.toLowerCase());
        if (idx < 0) return { content: [{ type: "text", text: `❌ Profile "${targetName}" not found.` }] };
        const p = cfg.servers[idx];
        const routeBefore = routeOf(p);
        if (typeof a.rename_to === "string") {
          if (a.rename_to.trim().length === 0) throw new Error("rename_to must be a non-empty string");
          if (cfg.servers.some((s, i) => i !== idx && s.name.toLowerCase() === a.rename_to.toLowerCase())) {
            return { content: [{ type: "text", text: `❌ Name "${a.rename_to}" already taken.` }] };
          }
          p.name = a.rename_to;
        }
        if (typeof a.host === "string") p.host = a.host;
        if (typeof a.port === "number") p.port = a.port;
        if (typeof a.username === "string") p.username = a.username;
        if (typeof a.password === "string") p.password = a.password;
        applyKeyArgs(ctx, p, a);
        if (typeof a.passphrase === "string") p.passphrase = a.passphrase;
        if (typeof a.description === "string") p.description = a.description;
        if (a.proxy === null) p.proxy = null;
        else if (a.proxy === false) delete p.proxy;
        else if (a.proxy && typeof a.proxy === "object") p.proxy = validateProxy(a.proxy);
        let note = "";
        if (a.reset_host_key === true && p.hostKeySha256) {
          delete p.hostKeySha256;
          note += " Host key pin dropped; the next ssh_connect_profile pins whatever key the server presents, so verify it.";
        }
        /* A route change keeps the pin (fail closed): the new route must present the same key. */
        if (routeOf(p) !== routeBefore) {
          if (p.hostKeySha256) {
            note += " The host key pin stays: the new route must lead to a server with the same key, otherwise connecting is refused.";
          } else if (ctx.mode === "remote" && typeof a.password !== "string" && dropUnpinnedPassword(p)) {
            note += ` ${PASSWORD_DROPPED_NOTE}`;
          }
        }
        return { content: [{ type: "text", text: `✅ Profile "${p.name}" updated.${note}` }] };
      });

      case "ssh_server_remove": return updateStore(ctx.store, (cfg) => {
        const targetName = String(args?.name);
        const before = cfg.servers.length;
        cfg.servers = cfg.servers.filter((s) => s.name.toLowerCase() !== targetName.toLowerCase());
        if (cfg.servers.length === before) {
          return { content: [{ type: "text", text: `❌ Profile "${targetName}" not found.` }] };
        }
        return { content: [{ type: "text", text: `✅ Profile "${targetName}" removed.` }] };
      });

      case "ssh_proxy_status": {
        const cfg = ctx.store.load();
        const lines: string[] = [];
        const override = ctx.proxyOverride;
        lines.push(`Global (config): ${describeProxy(cfg.proxy) || "—"}`);
        if (override.mode === "config") lines.push(`Runtime override: — (config is used)`);
        else if (override.mode === "disabled") lines.push(`Runtime override: DISABLED (proxy not applied to any connection)`);
        else lines.push(`Runtime override: FORCE → ${describeProxy(override.proxy)}`);
        const several = ctx.connections.size > 1;
        for (const c of ctx.connections.values()) {
          if (!c.session) continue;
          lines.push(`Current session${several ? ` (${c.name})` : ""}: ${c.session.proxyUsed ? describeProxy(c.session.proxyUsed) : "direct"}`);
        }
        return { content: [{ type: "text", text: lines.join("\n") }] };
      }

      case "ssh_proxy_set": {
        const proxy = validateProxy(args);
        const scope = (args?.scope as string) || "runtime";
        if (scope === "global") {
          const dropped = updateStore(ctx.store, (cfg) => {
            const note = dropInheritingPasswords(ctx, cfg, proxy);
            cfg.proxy = proxy;
            return note;
          });
          return { content: [{ type: "text", text: `✅ Global proxy saved to ${ctx.store.describe()}: ${describeProxy(proxy)}${dropped}` }] };
        }
        ctx.proxyOverride = { mode: "force", proxy };
        return {
          content: [{
            type: "text",
            text: `✅ Runtime proxy override: ${describeProxy(proxy)}\n(until restart or ssh_proxy_enable)`,
          }],
        };
      }

      case "ssh_proxy_disable": {
        const scope = (args?.scope as string) || "runtime";
        if (scope === "global") {
          const dropped = updateStore(ctx.store, (cfg) => {
            const note = dropInheritingPasswords(ctx, cfg, undefined);
            delete cfg.proxy;
            return note;
          });
          return { content: [{ type: "text", text: `✅ Global proxy removed from ${ctx.store.describe()}.${dropped}` }] };
        }
        ctx.proxyOverride = { mode: "disabled" };
        return {
          content: [{
            type: "text",
            text: "✅ Proxy disabled (runtime). All connections will go direct.\nssh_proxy_enable — return to config settings.",
          }],
        };
      }

      case "ssh_proxy_enable": {
        ctx.proxyOverride = { mode: "config" };
        return { content: [{ type: "text", text: "✅ Runtime override cleared. servers.json settings are used." }] };
      }

      case "ssh_execute":
      case "ssh_execute_background": {
        const c = conn();
        const command = args?.command as string;
        const background = name === "ssh_execute_background";
        const timeoutMs = background ? undefined : clampTimeout(args?.timeout_ms, maxExecTimeout(ctx));
        const dangerCheck = checkDangerousCommand(command);
        if (dangerCheck.isDangerous) {
          if (!c.session?.connected) throw new Error(`No active SSH connection to ${c.name}`);
          if (ctx.mode === "remote" && command.length > REMOTE_MAX_HELD_COMMAND_CHARS) {
            throw new Error(`Command is too long to hold for confirmation (max ${REMOTE_MAX_HELD_COMMAND_CHARS / 1024} KiB in remote mode); write it to a script with ssh_write_file and run that`);
          }
          const confirmId = generateId();
          holdConfirmation(ctx, ctx.pendingConfirmations, confirmId, {
            id: confirmId,
            command,
            reason: dangerCheck.reasons.join(", "),
            createdAt: new Date(),
            conn: c.key,
            sessionId: c.session.id,
            target: c.session.target,
            timeoutMs,
            background,
          });
          addLog(c, "warning", `Dangerous command requires confirmation: ${command}`);
          return {
            content: [{
              type: "text",
              text:
                `⚠️ DANGEROUS COMMAND REQUIRES CONFIRMATION\n\n` +
                `Command: ${command}\nServer: ${c.session.target} (connection: ${c.name})${background ? " (background job)" : ""}\n` +
                `Reasons: ${dangerCheck.reasons.join(", ")}\n\n` +
                `ssh_execute_dangerous { confirmation_id: "${confirmId}", confirm: true }`,
            }],
          };
        }
        if (background) return await startBackground(c, command);
        const result = await sshExecute(c, command, timeoutMs);
        return { content: [{ type: "text", text: result }] };
      }

      case "ssh_execute_dangerous": {
        pruneExpiredConfirmations(ctx);
        const confirmId = args?.confirmation_id as string;
        const confirm = args?.confirm as boolean;
        const pending = ctx.pendingConfirmations.get(confirmId);
        if (!pending) return confirmationGone(ctx, confirmId, "ssh_execute");
        if (typeof confirm !== "boolean") throw new Error("confirm must be true or false; the confirmation is still pending");
        ctx.pendingConfirmations.delete(confirmId);
        if (confirm !== true) {
          addLog(ctx.connections.get(pending.conn) ?? ctx, "info", `Command cancelled: ${pending.command}`);
          return { content: [{ type: "text", text: `✅ Cancelled: ${pending.command}` }] };
        }
        const c = conn();
        const problem = confirmationProblem(c, pending);
        if (problem) {
          return { content: [{ type: "text", text: `❌ Confirmation "${confirmId}" refused (${problem}). Re-run ${pending.background ? "ssh_execute_background" : "ssh_execute"} to get a new one.` }], isError: true };
        }
        addLog(c, "warning", `Dangerous command confirmed: ${pending.command}`);
        if (pending.background) return await startBackground(c, pending.command);
        const result = await sshExecute(c, pending.command, pending.timeoutMs);
        return { content: [{ type: "text", text: result }] };
      }

      case "ssh_read_background":
        return { content: [{ type: "text", text: readBackgroundJob(ctx, args?.job_id as string, args?.tail as number | undefined) }] };

      case "ssh_kill_background":
        return { content: [{ type: "text", text: await killBackgroundJob(ctx, args?.job_id as string) }] };

      case "ssh_list_background":
        return { content: [{ type: "text", text: listBackgroundJobs(ctx, profileArg(args)) }] };

      case "ssh_write_file":
        return { content: [{ type: "text", text: await sshUploadFile(conn(), args?.content as string, args?.remote_path as string) }] };

      case "ssh_read_file":
        return { content: [{ type: "text", text: await sshReadFile(conn(), args?.remote_path as string, hold) }] };

      case "ssh_list_dir":
        return { content: [{ type: "text", text: await sshListDir(conn(), (args?.remote_path as string) || ".") }] };

      case "ssh_download_file": {
        const c = conn();
        const result = await sshDownloadFile(c, args?.remote_path as string, (args?.as_base64 as boolean) || false, hold);
        const output = [
          `✅ File downloaded to temp store`,
          ``,
          `📋 Info:`,
          `  ID: ${result.tempFile.id}`,
          `  File: ${result.tempFile.filename}`,
          `  Size: ${formatBytes(result.tempFile.size)}`,
          `  Type: ${result.tempFile.isBinary ? "binary" : "text"}`,
          /* Remote clients must not learn the MCP host's filesystem layout. */
          ...(ctx.mode === "remote" ? [] : [`  Local: ${result.tempFile.localPath}`]),
          `  Remote: ${result.tempFile.remotePath}`,
          `  Connection: ${c.name}`,
          ``,
          result.base64 ? `📝 Content (base64):` : `📝 Content:`,
          `─────────────────────────────────────`,
          result.preview,
        ].join("\n");
        return { content: [{ type: "text", text: output }] };
      }

      case "ssh_temp_list": {
        const files = listTempFiles(ctx);
        if (files.length === 0) return { content: [{ type: "text", text: "📁 No temp files." }] };
        const list = files
          .map((f) => {
            const age = Math.round((Date.now() - f.downloadedAt.getTime()) / 1000 / 60);
            return [
              `📄 ID: ${f.id}`,
              `   File: ${f.filename}`,
              `   Size: ${formatBytes(f.size)} | ${f.isBinary ? "binary" : "text"}`,
              `   Server: ${f.serverHost}${f.connection ? ` (connection: ${f.connection})` : ""}`,
              `   Path: ${f.remotePath}`,
              `   Downloaded: ${age} min ago`,
            ].join("\n");
          })
          .join("\n\n");
        return { content: [{ type: "text", text: `📁 Temp files (${files.length}):\n\n${list}` }] };
      }

      case "ssh_temp_read": {
        const tempId = args?.temp_id as string;
        const asBase64 = (args?.as_base64 as boolean) || false;
        const tempFile = getTempFile(ctx, tempId);
        if (!tempFile) return { content: [{ type: "text", text: `❌ Temp "${tempId}" not found` }] };
        if (ctx.mode === "remote" && tempFile.size > REMOTE_INLINE_MAX_BYTES) {
          return {
            content: [{
              type: "text",
              text: `❌ Temp "${tempId}" is ${formatBytes(tempFile.size)}; remote mode returns at most ${formatBytes(REMOTE_INLINE_MAX_BYTES)} inline. Read parts of the file on the server with ssh_execute (head, tail, sed -n).`,
            }],
            isError: true,
          };
        }
        if (!hold.take(tempFile.size)) return { content: [{ type: "text", text: `❌ ${inlineBusyMessage()}` }], isError: true };
        const content = readTempFileContent(ctx, tempId);
        if (!content) return { content: [{ type: "text", text: `❌ Failed to read` }] };
        const output = asBase64 || tempFile.isBinary ? content.toString("base64") : content.toString("utf-8");
        return { content: [{ type: "text", text: output }] };
      }

      case "ssh_temp_write": {
        const tempId = args?.temp_id as string;
        const contentStr = args?.content as string;
        const isBase64 = (args?.is_base64 as boolean) || false;
        const tempFile = getTempFile(ctx, tempId);
        if (!tempFile) return { content: [{ type: "text", text: `❌ Temp "${tempId}" not found` }] };
        const content = isBase64 ? Buffer.from(contentStr, "base64") : Buffer.from(contentStr, "utf-8");
        if (updateTempFile(ctx, tempId, content)) {
          return {
            content: [{
              type: "text",
              text: `✅ Temp updated: ${tempFile.filename}\nSize: ${formatBytes(content.length)}`,
            }],
          };
        }
        return { content: [{ type: "text", text: `❌ Failed to update` }] };
      }

      case "ssh_temp_upload":
        return { content: [{ type: "text", text: await sshUploadFromTemp(conn(), args?.temp_id as string, args?.remote_path as string | undefined) }] };

      case "ssh_temp_delete": {
        const ok = deleteTempFile(ctx, args?.temp_id as string);
        return { content: [{ type: "text", text: ok ? "✅ Removed" : "❌ Not found" }] };
      }

      case "ssh_temp_cleanup": {
        const count = cleanupAllTempFiles(ctx);
        return { content: [{ type: "text", text: `✅ Removed: ${count}` }] };
      }

      case "ssh_temp_path": {
        const tempFile = getTempFile(ctx, args?.temp_id as string);
        if (!tempFile) return { content: [{ type: "text", text: `❌ Not found` }] };
        return { content: [{ type: "text", text: `📄 ${tempFile.localPath}` }] };
      }

      case "ssh_file_info":
        return { content: [{ type: "text", text: await sshFileInfo(conn(), args?.remote_path as string) }] };

      case "ssh_mkdir":
        return { content: [{ type: "text", text: await sshMkdir(conn(), args?.remote_path as string, (args?.recursive as boolean) || false) }] };

      case "ssh_rename":
        return { content: [{ type: "text", text: await sshRename(conn(), args?.old_path as string, args?.new_path as string) }] };

      case "ssh_copy":
        return { content: [{ type: "text", text: await sshCopy(conn(), args?.src_path as string, args?.dest_path as string) }] };

      case "ssh_chmod":
        return { content: [{ type: "text", text: await sshChmod(conn(), args?.remote_path as string, args?.mode as string) }] };

      case "ssh_delete": {
        const c = conn();
        const remotePath = args?.remote_path as string;
        const isDirectory = (args?.is_directory as boolean) || false;
        if (!c.session?.connected) throw new Error(`No active SSH connection to ${c.name}`);
        if (ctx.mode === "remote" && String(remotePath).length > 4096) throw new Error("Path is too long (max 4096 characters)");
        const confirmId = generateId();
        holdConfirmation(ctx, ctx.pendingDeleteConfirmations, confirmId, {
          id: confirmId,
          path: remotePath,
          isDirectory,
          createdAt: new Date(),
          conn: c.key,
          sessionId: c.session.id,
          target: c.session.target,
        });
        addLog(c, "warning", `Deletion requires confirmation: ${remotePath}`);
        return {
          content: [{
            type: "text",
            text:
              `⚠️ DELETION REQUIRES CONFIRMATION\n\nPath: ${remotePath}\nKind: ${isDirectory ? "Directory" : "File"}\n` +
              `Server: ${c.session.target} (connection: ${c.name})\n\n` +
              `ssh_delete_confirm { confirmation_id: "${confirmId}", confirm: true }`,
          }],
        };
      }

      case "ssh_delete_confirm": {
        pruneExpiredConfirmations(ctx);
        const confirmId = args?.confirmation_id as string;
        const confirm = args?.confirm as boolean;
        const pending = ctx.pendingDeleteConfirmations.get(confirmId);
        if (!pending) return confirmationGone(ctx, confirmId, "ssh_delete");
        if (typeof confirm !== "boolean") throw new Error("confirm must be true or false; the confirmation is still pending");
        ctx.pendingDeleteConfirmations.delete(confirmId);
        if (confirm !== true) {
          addLog(ctx.connections.get(pending.conn) ?? ctx, "info", `Deletion cancelled: ${pending.path}`);
          return { content: [{ type: "text", text: `✅ Cancelled: ${pending.path}` }] };
        }
        const c = conn();
        const problem = confirmationProblem(c, pending);
        if (problem) {
          return { content: [{ type: "text", text: `❌ Confirmation "${confirmId}" refused (${problem}). Re-run ssh_delete to get a new one.` }], isError: true };
        }
        addLog(c, "warning", `Deletion confirmed: ${pending.path}`);
        return { content: [{ type: "text", text: await sshDelete(c, pending.path, pending.isDirectory) }] };
      }

      case "ssh_get_logs": {
        const limit = args?.limit as number | undefined;
        const only = profileArg(args);
        const keys = only === undefined ? undefined : [findConn(ctx, only)?.key ?? keysOfName(only)].flat();
        const entries = keys === undefined ? ctx.logs : ctx.logs.filter((e) => e.connKey !== undefined && keys.includes(e.connKey));
        const logs = formatLogs(entries, limit);
        return { content: [{ type: "text", text: logs || "No log entries yet" }] };
      }

      case "ssh_status": {
        const only = profileArg(args);
        const conns = only === undefined ? [...ctx.connections.values()] : [findConn(ctx, only)].filter((c): c is Conn => !!c);
        if (conns.length === 0) {
          return { content: [{ type: "text", text: only === undefined ? "❌ No active connection" : `❌ No connection named "${only}". Open: ${connectionNames(ctx)}` }] };
        }
        const blocks = conns.map((c) => {
          const s = c.session;
          const cfg = s?.config ?? c.lastConnect?.config;
          const status = s?.connected ? "🟢 Connected" : c.connecting ? "🟡 Connecting" : "🔴 Disconnected (reconnects on next use)";
          const duration = s ? Math.round((Date.now() - s.startTime.getTime()) / 1000) : 0;
          const proxyUsed = s ? s.proxyUsed : c.lastConnect?.proxy;
          const keySeen = s?.hostKeySha256 ?? c.lastConnect?.hostKeySha256;
          const keyPinned = s ? s.hostKeyPinned : c.lastConnect?.hostKeyPinned;
          const keyLine = keySeen
            ? `\nHost key: ${keySeen} (${keyPinned ? "pinned" : "not pinned: raw ssh_connect, held only for auto-reconnect"})`
            : "";
          const entries = ctx.logs.filter((e) => e.conn === c.name).length;
          return (
            `Connection: ${c.name}\n${status}\n` +
            (cfg ? `Host: ${cfg.host}:${cfg.port || 22}\nUser: ${cfg.username}\n` : "") +
            `Session time: ${duration}s\nLog entries: ${entries}\nProxy: ${proxyUsed ? describeProxy(proxyUsed) : "direct"}${keyLine}`
          );
        });
        const header = conns.length > 1 ? `${conns.length} connections (pass profile to choose one):\n\n` : "";
        return { content: [{ type: "text", text: header + blocks.join("\n\n") }] };
      }

      case "ssh_disconnect": {
        const cleanup = (args?.cleanup_temp as boolean) || false;
        const all = [...ctx.connections.values()];
        if (args?.all === true) {
          if (all.length === 0) return { content: [{ type: "text", text: "No active connection" }] };
          const lines = all.map((c) => sshDisconnect(c, cleanup));
          if (cleanup) {
            const rest = cleanupAllTempFiles(ctx);
            if (rest > 0) lines.push(`🗑️ Other temp files removed: ${rest}`);
          }
          return { content: [{ type: "text", text: lines.join("\n") }] };
        }
        const only = profileArg(args);
        if (only !== undefined) {
          const c = findConn(ctx, only);
          if (!c) return { content: [{ type: "text", text: `❌ No connection named "${only}". Open: ${connectionNames(ctx)}` }], isError: true };
          return { content: [{ type: "text", text: sshDisconnect(c, cleanup) }] };
        }
        if (all.length === 0) return { content: [{ type: "text", text: "No active connection" }] };
        if (all.length > 1) {
          return {
            content: [{
              type: "text",
              text: `❌ ${all.length} connections are open (${connectionNames(ctx)}); pass profile to close one, or all: true. Nothing was closed.`,
            }],
            isError: true,
          };
        }
        return { content: [{ type: "text", text: sshDisconnect(all[0], cleanup) }] };
      }

      case "ssh_pending_confirmations": {
        pruneExpiredConfirmations(ctx);
        if (ctx.pendingConfirmations.size === 0) return { content: [{ type: "text", text: "No pending confirmations" }] };
        const list = Array.from(ctx.pendingConfirmations.values())
          .map((p) => `ID: ${p.id}\nServer: ${p.target} (connection: ${ctx.connections.get(p.conn)?.name ?? p.conn})\nCommand: ${p.command}\nReason: ${p.reason}`)
          .join("\n\n");
        return { content: [{ type: "text", text: list }] };
      }

      case "ssh_upload":
        return {
          content: [{
            type: "text",
            text: await sshUpload(
              conn(),
              args?.local_path as string,
              args?.remote_path as string,
              (args?.exclude as string[]) || []
            ),
          }],
        };

      case "ssh_pin_host_keys": {
        const cfg = ctx.store.load();
        const lines: string[] = [];
        let targets: ServerProfile[];
        if (Array.isArray(args?.profiles)) {
          targets = [];
          for (const n of args.profiles as unknown[]) {
            const p = getServerProfile(cfg, String(n));
            if (!p) lines.push(`${String(n)} → ❌ no such profile`);
            else if (!targets.includes(p)) targets.push(p);
          }
        } else {
          targets = cfg.servers.filter((s) => !s.hostKeySha256);
        }
        if (targets.length === 0 && lines.length === 0) {
          return { content: [{ type: "text", text: "Every profile already has a pinned host key." }] };
        }
        const routeKey = (p: ServerProfile, c: ServersConfig) =>
          JSON.stringify([p.host, p.port || 22, resolveProxyForProfile(ctx, p, c) ?? null]);
        /* Inside the call deadline: pins nobody would see must not be written after the call gave up. */
        const until = Date.now() + DEFAULT_TRANSFER_TIMEOUT_MS - 30_000;
        const scanned = await mapLimit(targets, SCAN_CONCURRENCY, async (p) => {
          const route = routeKey(p, cfg);
          if (Date.now() > until) return { name: p.name, route, error: "not scanned: the call ran out of time; call again for the rest" };
          try {
            return { name: p.name, route, fp: await scanHostKey(p.host, p.port || 22, resolveProxyForProfile(ctx, p, cfg)) };
          } catch (e) {
            return { name: p.name, route, error: e instanceof Error ? e.message : String(e) };
          }
        });
        if (Date.now() > until + 25_000) throw new Error("Scanning took too long; nothing was pinned. Call again with fewer profiles.");
        /* Re-checked under the store lock: a pin is written only for the route that was scanned, never over a pin. */
        lines.push(...updateStore(ctx.store, (fresh) => scanned.map((r) => {
          if (r.fp === undefined) return `${r.name} → ❌ ${r.error}`;
          const f = getServerProfile(fresh, r.name);
          if (!f) return `${r.name} → ❌ removed while scanning; not pinned`;
          if (routeKey(f, fresh) !== r.route) return `${r.name} → ❌ host, port or proxy changed while scanning; not pinned`;
          if (f.hostKeySha256) {
            const pinned = normalizeHostKeyFingerprint(f.hostKeySha256);
            return pinned === r.fp
              ? `${r.name} → ${r.fp} (matches the existing pin)`
              : `${r.name} → ⚠️ MISMATCH: pinned ${pinned}, server presented ${r.fp}. Pin left unchanged; stop and have the user verify the key on the server itself.`;
          }
          f.hostKeySha256 = r.fp;
          addLog(ctx, "info", `Pinned host key ${r.fp} for profile ${f.name} (scan)`);
          return `${r.name} → ${r.fp} (pinned)`;
        })));
        return {
          content: [{
            type: "text",
            text:
              `🔐 Host keys (scanned without authenticating; no credentials were sent). ` +
              `Check new pins against the servers (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub):\n\n${lines.join("\n")}`,
          }],
        };
      }

      default:
        return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    addLog(target ?? ctx, "error", message);
    return { content: [{ type: "text", text: `❌ Error: ${message}` }], isError: true };
  }
}
