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
} from "./state.js";
import type { SessionCtx } from "./state.js";
import { generateId, formatBytes, formatLogs } from "./utils.js";
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
  "ssh_list_background",
  "ssh_temp_list",
  "ssh_temp_read",
  "ssh_temp_write",
  "ssh_temp_delete",
  "ssh_temp_cleanup",
  "ssh_temp_path",
  "ssh_get_logs",
]);

const TRANSFER_TOOLS = new Set(["ssh_upload", "ssh_download_file", "ssh_temp_upload", "ssh_copy"]);

/* Pending confirmations hold the full command until confirmed; bounded so a loop of dangerous calls cannot pile up. */
const MAX_PENDING_CONFIRMATIONS = 16;
const REMOTE_MAX_HELD_COMMAND_CHARS = 64 * 1024;

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
function confirmationProblem(ctx: SessionCtx, p: { sessionId: string; target: string; createdAt: Date }): string | null {
  if (Date.now() - p.createdAt.getTime() > CONFIRMATION_TTL_MS) return "expired";
  if (ctx.session?.id !== p.sessionId) {
    return `issued for ${p.target} in an earlier connection; current: ${ctx.session?.target ?? "not connected"}`;
  }
  return null;
}

function pruneExpiredConfirmations(ctx: SessionCtx): void {
  const now = Date.now();
  for (const map of [ctx.pendingConfirmations, ctx.pendingDeleteConfirmations] as Map<string, { createdAt: Date }>[]) {
    for (const [id, p] of map) if (now - p.createdAt.getTime() > CONFIRMATION_TTL_MS) map.delete(id);
  }
}

/* Map order is insertion order: beyond the cap the oldest pending confirmation is dropped. */
function holdConfirmation<T extends { createdAt: Date }>(ctx: SessionCtx, map: Map<string, T>, id: string, entry: T): void {
  pruneExpiredConfirmations(ctx);
  for (const oldest of map.keys()) {
    if (map.size < MAX_PENDING_CONFIRMATIONS) break;
    map.delete(oldest);
  }
  map.set(id, entry);
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
function pinOnFirstUse(ctx: SessionCtx, profile: ServerProfile, seen: string | undefined): string {
  if (!seen || !ctx.session) return "⚠️ Host key was not observed; profile not pinned.";
  const endpoint = (s: ServerProfile) => `${s.username}@${s.host}:${s.port || 22}`;
  let outcome: "changed" | "matches" | "pinned";
  try {
    /* Check and pin under one store lock: a pin the owner sets meanwhile must win, not be overwritten. */
    outcome = updateStore(ctx.store, (cfg): "changed" | "matches" | "pinned" => {
      const fresh = cfg.servers.find((s) => s.name.toLowerCase() === profile.name.toLowerCase());
      if (!fresh || endpoint(fresh) !== endpoint(profile)) return "changed";
      if (fresh.hostKeySha256) {
        const pinned = normalizeHostKeyFingerprint(fresh.hostKeySha256);
        if (pinned !== seen) throw new HostKeyMismatchError(endpoint(profile), pinned, seen, ctx.mode);
        return "matches";
      }
      fresh.hostKeySha256 = seen;
      return "pinned";
    });
  } catch (err) {
    if (err instanceof HostKeyMismatchError) {
      sshDisconnect(ctx);
      throw err;
    }
    return `⚠️ Connected, but the host key pin could not be saved (${err instanceof Error ? err.message : String(err)}); the profile stays unpinned.`;
  }
  if (outcome === "changed") return "⚠️ Profile changed while connecting; host key not pinned.";
  markPinned(ctx);
  if (outcome === "matches") return `🔐 Host key ${seen} matches the pin.`;
  addLog(ctx, "info", `Pinned host key ${seen} for profile ${profile.name}`);
  return (
    `🔐 First connection with this profile: pinned host key ${seen} (trust on first use). ` +
    `Check it against the server (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub); any other key will now be refused.`
  );
}

function maxExecTimeout(ctx: SessionCtx): number | undefined {
  return ctx.mode === "remote" ? REMOTE_MAX_EXEC_TIMEOUT_MS : undefined;
}

function markPinned(ctx: SessionCtx): void {
  if (ctx.session) ctx.session.hostKeyPinned = true;
  if (ctx.lastConnect) ctx.lastConnect.hostKeyPinned = true;
}

async function startBackground(ctx: SessionCtx, command: string): Promise<{ content: { type: "text"; text: string }[] }> {
  const { id } = await sshExecuteBackground(ctx, command);
  return {
    content: [{
      type: "text",
      text:
        `🟢 Background job started\njob_id: ${id}\ncommand: ${command}\n\n` +
        `Read:  ssh_read_background({job_id:"${id}"})\n` +
        `Stop:  ssh_kill_background({job_id:"${id}"})`,
    }],
  };
}

export async function handleToolCall(ctx: SessionCtx, name: string, args: any): Promise<{
  content: { type: "text"; text: string }[];
  isError?: boolean;
}> {
  /* Remote mode: inline content this call buffers stays reserved until its result has been serialized. */
  const hold = new ReadBudget(ctx, "inline");
  try {
    if (!isToolAvailable(ctx.mode, name, ctx.scoped)) {
      const where = ctx.scoped && isToolAvailable(ctx.mode, name) ? "to a connector grant (its profiles are read-only)" : "in remote mode";
      return { content: [{ type: "text", text: `❌ ${name} is not available ${where}` }], isError: true };
    }
    let reconnectNote: string | null = null;
    if (!SESSION_FREE_TOOLS.has(name)) {
      reconnectNote = await ensureConnected(ctx);
    }
    const requested = name === "ssh_execute_dangerous" ? ctx.pendingConfirmations.get(args?.confirmation_id)?.timeoutMs : args?.timeout_ms;
    const execLimit = (clampTimeout(requested, maxExecTimeout(ctx)) ?? DEFAULT_EXEC_TIMEOUT_MS) + 5_000;
    const deadline = name === "ssh_execute" || name === "ssh_execute_dangerous" ? execLimit : TRANSFER_TOOLS.has(name) ? DEFAULT_TRANSFER_TIMEOUT_MS : DEFAULT_SFTP_TIMEOUT_MS;
    const result = await withDeadline(ctx, dispatch(ctx, name, args, hold), deadline, name);
    if (reconnectNote && result.content.length > 0 && result.content[0].type === "text") {
      result.content[0].text = `${reconnectNote}\n${result.content[0].text}`;
    }
    return result;
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return { content: [{ type: "text", text: `❌ Error: ${msg}` }], isError: true };
  } finally {
    /* The SDK serializes the result in the microtasks right after this returns; a macrotask runs after that. */
    setImmediate(() => hold.release());
  }
}

async function dispatch(ctx: SessionCtx, name: string, args: any, hold: ReadBudget): Promise<{
  content: { type: "text"; text: string }[];
  isError?: boolean;
}> {
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
        const result = await sshConnect(ctx, config, proxy);
        return { content: [{ type: "text", text: result }] };
      }

      case "ssh_connect_profile": {
        const profileName = args?.profile_name as string;
        const cfg = ctx.store.load();
        const profile = getServerProfile(cfg, profileName);
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
        if (ctx.mode === "remote" && !profile.hostKeySha256 && ctx.proxyOverride.mode !== "config") {
          return {
            content: [{
              type: "text",
              text:
                `❌ Profile "${profile.name}" has no pinned host key yet. Its first connection must take the route stored in the vault, ` +
                `not this session's proxy override: run ssh_proxy_enable first, or have the owner pin it (mcp-sshpilot vault pin-host-key).`,
            }],
            isError: true,
          };
        }
        const config = profileToConnectConfig(ctx.store, profile);
        const proxy = resolveProxyForProfile(ctx, profile, cfg);
        const result = await sshConnect(ctx, config, proxy, { expectedHostKey: profile.hostKeySha256, pinned: !!profile.hostKeySha256 });
        const seen = ctx.session?.hostKeySha256;
        const keyNote = profile.hostKeySha256
          ? `🔐 Host key ${seen} matches the pin.`
          : pinOnFirstUse(ctx, profile, seen);
        return {
          content: [{
            type: "text",
            text: `${result}\n(profile: ${profile.name}${profile.description ? ` — ${profile.description}` : ""})\n${keyNote}`,
          }],
        };
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
            return `• ${p.name} → ${p.host}${desc}${px}`;
          })
          .join("\n");
        return { content: [{ type: "text", text: `📋 Profiles:\n\n${list}` }] };
      }

      case "ssh_server_add": return updateStore(ctx.store, (cfg) => {
        const a = args || {};
        const newName = String(a.name);
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
        if (typeof a.rename_to === "string" && a.rename_to.length > 0) {
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
        if (ctx.session) {
          lines.push(`Current session: ${ctx.session.proxyUsed ? describeProxy(ctx.session.proxyUsed) : "direct"}`);
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
        const command = args?.command as string;
        const background = name === "ssh_execute_background";
        const timeoutMs = background ? undefined : clampTimeout(args?.timeout_ms, maxExecTimeout(ctx));
        const dangerCheck = checkDangerousCommand(command);
        if (dangerCheck.isDangerous) {
          if (!ctx.session?.connected) throw new Error("No active SSH connection");
          if (ctx.mode === "remote" && command.length > REMOTE_MAX_HELD_COMMAND_CHARS) {
            throw new Error(`Command is too long to hold for confirmation (max ${REMOTE_MAX_HELD_COMMAND_CHARS / 1024} KiB in remote mode); write it to a script with ssh_write_file and run that`);
          }
          const confirmId = generateId();
          holdConfirmation(ctx, ctx.pendingConfirmations, confirmId, {
            id: confirmId,
            command,
            reason: dangerCheck.reasons.join(", "),
            createdAt: new Date(),
            sessionId: ctx.session.id,
            target: ctx.session.target,
            timeoutMs,
            background,
          });
          addLog(ctx, "warning", `Dangerous command requires confirmation: ${command}`);
          return {
            content: [{
              type: "text",
              text:
                `⚠️ DANGEROUS COMMAND REQUIRES CONFIRMATION\n\n` +
                `Command: ${command}\nServer: ${ctx.session.target}${background ? " (background job)" : ""}\n` +
                `Reasons: ${dangerCheck.reasons.join(", ")}\n\n` +
                `ssh_execute_dangerous { confirmation_id: "${confirmId}", confirm: true }`,
            }],
          };
        }
        if (background) return await startBackground(ctx, command);
        const result = await sshExecute(ctx, command, timeoutMs);
        return { content: [{ type: "text", text: result }] };
      }

      case "ssh_execute_dangerous": {
        pruneExpiredConfirmations(ctx);
        const confirmId = args?.confirmation_id as string;
        const confirm = args?.confirm as boolean;
        const pending = ctx.pendingConfirmations.get(confirmId);
        if (!pending) return { content: [{ type: "text", text: `❌ Confirmation "${confirmId}" not found or expired` }] };
        ctx.pendingConfirmations.delete(confirmId);
        if (!confirm) {
          addLog(ctx, "info", `Command cancelled: ${pending.command}`);
          return { content: [{ type: "text", text: `✅ Cancelled: ${pending.command}` }] };
        }
        const problem = confirmationProblem(ctx, pending);
        if (problem) {
          return { content: [{ type: "text", text: `❌ Confirmation "${confirmId}" refused (${problem}). Re-run ${pending.background ? "ssh_execute_background" : "ssh_execute"} to get a new one.` }], isError: true };
        }
        addLog(ctx, "warning", `Dangerous command confirmed: ${pending.command}`);
        if (pending.background) return await startBackground(ctx, pending.command);
        const result = await sshExecute(ctx, pending.command, pending.timeoutMs);
        return { content: [{ type: "text", text: result }] };
      }

      case "ssh_read_background":
        return { content: [{ type: "text", text: readBackgroundJob(ctx, args?.job_id as string, args?.tail as number | undefined) }] };

      case "ssh_kill_background":
        return { content: [{ type: "text", text: await killBackgroundJob(ctx, args?.job_id as string) }] };

      case "ssh_list_background":
        return { content: [{ type: "text", text: listBackgroundJobs(ctx) }] };

      case "ssh_write_file":
        return { content: [{ type: "text", text: await sshUploadFile(ctx, args?.content as string, args?.remote_path as string) }] };

      case "ssh_read_file":
        return { content: [{ type: "text", text: await sshReadFile(ctx, args?.remote_path as string, hold) }] };

      case "ssh_list_dir":
        return { content: [{ type: "text", text: await sshListDir(ctx, (args?.remote_path as string) || ".") }] };

      case "ssh_download_file": {
        const result = await sshDownloadFile(ctx, args?.remote_path as string, (args?.as_base64 as boolean) || false, hold);
        const output = [
          `✅ File downloaded to temp store`,
          ``,
          `📋 Info:`,
          `  ID: ${result.tempFile.id}`,
          `  File: ${result.tempFile.filename}`,
          `  Size: ${formatBytes(result.tempFile.size)}`,
          `  Type: ${result.tempFile.isBinary ? "binary" : "text"}`,
          /* The MCP host's filesystem layout is none of a remote client's business. */
          ...(ctx.mode === "remote" ? [] : [`  Local: ${result.tempFile.localPath}`]),
          `  Remote: ${result.tempFile.remotePath}`,
          ``,
          `📝 Content:`,
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
              `   Server: ${f.serverHost}`,
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
        return { content: [{ type: "text", text: await sshUploadFromTemp(ctx, args?.temp_id as string, args?.remote_path as string | undefined) }] };

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
        return { content: [{ type: "text", text: await sshFileInfo(ctx, args?.remote_path as string) }] };

      case "ssh_mkdir":
        return { content: [{ type: "text", text: await sshMkdir(ctx, args?.remote_path as string, (args?.recursive as boolean) || false) }] };

      case "ssh_rename":
        return { content: [{ type: "text", text: await sshRename(ctx, args?.old_path as string, args?.new_path as string) }] };

      case "ssh_copy":
        return { content: [{ type: "text", text: await sshCopy(ctx, args?.src_path as string, args?.dest_path as string) }] };

      case "ssh_chmod":
        return { content: [{ type: "text", text: await sshChmod(ctx, args?.remote_path as string, args?.mode as string) }] };

      case "ssh_delete": {
        const remotePath = args?.remote_path as string;
        const isDirectory = (args?.is_directory as boolean) || false;
        if (!ctx.session?.connected) throw new Error("No active SSH connection");
        if (ctx.mode === "remote" && String(remotePath).length > 4096) throw new Error("Path is too long (max 4096 characters)");
        const confirmId = generateId();
        holdConfirmation(ctx, ctx.pendingDeleteConfirmations, confirmId, {
          id: confirmId,
          path: remotePath,
          isDirectory,
          createdAt: new Date(),
          sessionId: ctx.session.id,
          target: ctx.session.target,
        });
        addLog(ctx, "warning", `Deletion requires confirmation: ${remotePath}`);
        return {
          content: [{
            type: "text",
            text:
              `⚠️ DELETION REQUIRES CONFIRMATION\n\nPath: ${remotePath}\nKind: ${isDirectory ? "Directory" : "File"}\n\n` +
              `ssh_delete_confirm { confirmation_id: "${confirmId}", confirm: true }`,
          }],
        };
      }

      case "ssh_delete_confirm": {
        pruneExpiredConfirmations(ctx);
        const confirmId = args?.confirmation_id as string;
        const confirm = args?.confirm as boolean;
        const pending = ctx.pendingDeleteConfirmations.get(confirmId);
        if (!pending) return { content: [{ type: "text", text: `❌ Confirmation "${confirmId}" not found or expired` }] };
        ctx.pendingDeleteConfirmations.delete(confirmId);
        if (!confirm) {
          addLog(ctx, "info", `Deletion cancelled: ${pending.path}`);
          return { content: [{ type: "text", text: `✅ Cancelled: ${pending.path}` }] };
        }
        const problem = confirmationProblem(ctx, pending);
        if (problem) {
          return { content: [{ type: "text", text: `❌ Confirmation "${confirmId}" refused (${problem}). Re-run ssh_delete to get a new one.` }], isError: true };
        }
        addLog(ctx, "warning", `Deletion confirmed: ${pending.path}`);
        return { content: [{ type: "text", text: await sshDelete(ctx, pending.path, pending.isDirectory) }] };
      }

      case "ssh_get_logs": {
        const limit = args?.limit as number | undefined;
        if (!ctx.session) return { content: [{ type: "text", text: "No active session." }] };
        const logs = formatLogs(ctx.session.logs, limit);
        return { content: [{ type: "text", text: logs || "No log entries yet" }] };
      }

      case "ssh_status": {
        if (!ctx.session) return { content: [{ type: "text", text: "❌ No active connection" }] };
        const duration = Math.round((Date.now() - ctx.session.startTime.getTime()) / 1000);
        const status = ctx.session.connected ? "🟢 Connected" : "🔴 Disconnected";
        const proxyLine = ctx.session.proxyUsed
          ? `\nProxy: ${describeProxy(ctx.session.proxyUsed)}`
          : "\nProxy: direct";
        const keyLine = ctx.session.hostKeySha256
          ? `\nHost key: ${ctx.session.hostKeySha256} (${ctx.session.hostKeyPinned ? "pinned" : "not pinned: raw ssh_connect, held only for auto-reconnect"})`
          : "";
        return {
          content: [{
            type: "text",
            text:
              `${status}\nHost: ${ctx.session.config.host}:${ctx.session.config.port || 22}\n` +
              `User: ${ctx.session.config.username}\nSession time: ${duration}s\n` +
              `Log entries: ${ctx.session.logs.length}${proxyLine}${keyLine}`,
          }],
        };
      }

      case "ssh_disconnect":
        return { content: [{ type: "text", text: sshDisconnect(ctx, (args?.cleanup_temp as boolean) || false) }] };

      case "ssh_pending_confirmations": {
        pruneExpiredConfirmations(ctx);
        if (ctx.pendingConfirmations.size === 0) return { content: [{ type: "text", text: "No pending confirmations" }] };
        const list = Array.from(ctx.pendingConfirmations.values())
          .map((p) => `ID: ${p.id}\nServer: ${p.target}\nCommand: ${p.command}\nReason: ${p.reason}`)
          .join("\n\n");
        return { content: [{ type: "text", text: list }] };
      }

      case "ssh_upload":
        return {
          content: [{
            type: "text",
            text: await sshUpload(
              ctx,
              args?.local_path as string,
              args?.remote_path as string,
              (args?.exclude as string[]) || []
            ),
          }],
        };

      default:
        return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    addLog(ctx, "error", message);
    return { content: [{ type: "text", text: `❌ Error: ${message}` }], isError: true };
  }
}
