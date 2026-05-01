import type { ConnectConfig } from "ssh2";
import type { ServerProfile, ProxyConfig } from "./types.js";
import {
  state,
  addLog,
  pendingConfirmations,
  pendingDeleteConfirmations,
  setProxyOverride,
  getProxyOverride,
} from "./state.js";
import { generateId, formatBytes, formatLogs } from "./utils.js";
import { checkDangerousCommand } from "./danger.js";
import {
  loadServersConfig,
  saveServersConfig,
  getServerProfile,
  listProfiles,
  profileToConnectConfig,
  SERVERS_CONFIG_PATH,
} from "./config.js";
import { describeProxy, validateProxy, resolveProxyForProfile } from "./proxy.js";
import {
  sshConnect,
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
} from "./ssh-fs.js";
import {
  listTempFiles,
  getTempFile,
  readTempFileContent,
  updateTempFile,
  deleteTempFile,
  cleanupAllTempFiles,
} from "./temp.js";

export async function handleToolCall(name: string, args: any): Promise<{
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
        const override = getProxyOverride();
        if (args?.proxy) proxy = validateProxy(args.proxy);
        else if (override.mode === "force") proxy = override.proxy;
        else if (override.mode === "config") proxy = loadServersConfig().proxy;
        const result = await sshConnect(config, proxy);
        return { content: [{ type: "text", text: result }] };
      }

      case "ssh_connect_profile": {
        const profileName = args?.profile_name as string;
        const profile = getServerProfile(profileName);
        if (!profile) {
          const profiles = listProfiles();
          const available =
            profiles.length > 0
              ? `\n\nAvailable: ${profiles.map((p) => p.name).join(", ")}`
              : "\n\nservers.json is empty. Use ssh_server_add or copy servers.example.json.";
          return {
            content: [{ type: "text", text: `❌ Profile "${profileName}" not found.${available}` }],
          };
        }
        const cfg = loadServersConfig();
        const config = profileToConnectConfig(profile);
        const proxy = resolveProxyForProfile(profile, cfg);
        const result = await sshConnect(config, proxy);
        return {
          content: [{
            type: "text",
            text: `${result}\n(profile: ${profile.name}${profile.description ? ` — ${profile.description}` : ""})`,
          }],
        };
      }

      case "ssh_list_profiles": {
        const profiles = listProfiles();
        if (profiles.length === 0) {
          return {
            content: [{
              type: "text",
              text: `📋 No profiles.\nAdd one via ssh_server_add or create ${SERVERS_CONFIG_PATH}`,
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

      case "ssh_server_add": {
        const cfg = loadServersConfig();
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
        if (typeof a.privateKeyPath === "string") profile.privateKeyPath = a.privateKeyPath;
        if (typeof a.passphrase === "string") profile.passphrase = a.passphrase;
        if (typeof a.description === "string") profile.description = a.description;
        if (a.proxy === null) profile.proxy = null;
        else if (a.proxy && typeof a.proxy === "object") profile.proxy = validateProxy(a.proxy);
        cfg.servers.push(profile);
        saveServersConfig(cfg);
        return {
          content: [{
            type: "text",
            text: `✅ Profile "${newName}" added (${profile.host}:${profile.port || 22}).`,
          }],
        };
      }

      case "ssh_server_update": {
        const cfg = loadServersConfig();
        const a = args || {};
        const targetName = String(a.name);
        const idx = cfg.servers.findIndex((s) => s.name.toLowerCase() === targetName.toLowerCase());
        if (idx < 0) return { content: [{ type: "text", text: `❌ Profile "${targetName}" not found.` }] };
        const p = cfg.servers[idx];
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
        if (typeof a.privateKeyPath === "string") p.privateKeyPath = a.privateKeyPath;
        if (typeof a.passphrase === "string") p.passphrase = a.passphrase;
        if (typeof a.description === "string") p.description = a.description;
        if (a.proxy === null) p.proxy = null;
        else if (a.proxy === false) delete p.proxy;
        else if (a.proxy && typeof a.proxy === "object") p.proxy = validateProxy(a.proxy);
        saveServersConfig(cfg);
        return { content: [{ type: "text", text: `✅ Profile "${p.name}" updated.` }] };
      }

      case "ssh_server_remove": {
        const cfg = loadServersConfig();
        const targetName = String(args?.name);
        const before = cfg.servers.length;
        cfg.servers = cfg.servers.filter((s) => s.name.toLowerCase() !== targetName.toLowerCase());
        if (cfg.servers.length === before) {
          return { content: [{ type: "text", text: `❌ Profile "${targetName}" not found.` }] };
        }
        saveServersConfig(cfg);
        return { content: [{ type: "text", text: `✅ Profile "${targetName}" removed.` }] };
      }

      case "ssh_proxy_status": {
        const cfg = loadServersConfig();
        const lines: string[] = [];
        const override = getProxyOverride();
        lines.push(`Global (config): ${describeProxy(cfg.proxy) || "—"}`);
        if (override.mode === "config") lines.push(`Runtime override: — (config is used)`);
        else if (override.mode === "disabled") lines.push(`Runtime override: DISABLED (proxy not applied to any connection)`);
        else lines.push(`Runtime override: FORCE → ${describeProxy(override.proxy)}`);
        if (state.session) {
          lines.push(`Current session: ${state.session.proxyUsed ? describeProxy(state.session.proxyUsed) : "direct"}`);
        }
        return { content: [{ type: "text", text: lines.join("\n") }] };
      }

      case "ssh_proxy_set": {
        const proxy = validateProxy(args);
        const scope = (args?.scope as string) || "runtime";
        if (scope === "global") {
          const cfg = loadServersConfig();
          cfg.proxy = proxy;
          saveServersConfig(cfg);
          return { content: [{ type: "text", text: `✅ Global proxy saved to servers.json: ${describeProxy(proxy)}` }] };
        }
        setProxyOverride({ mode: "force", proxy });
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
          const cfg = loadServersConfig();
          delete cfg.proxy;
          saveServersConfig(cfg);
          return { content: [{ type: "text", text: "✅ Global proxy removed from servers.json." }] };
        }
        setProxyOverride({ mode: "disabled" });
        return {
          content: [{
            type: "text",
            text: "✅ Proxy disabled (runtime). All connections will go direct.\nssh_proxy_enable — return to config settings.",
          }],
        };
      }

      case "ssh_proxy_enable": {
        setProxyOverride({ mode: "config" });
        return { content: [{ type: "text", text: "✅ Runtime override cleared. servers.json settings are used." }] };
      }

      case "ssh_execute": {
        const command = args?.command as string;
        const timeoutMs = args?.timeout_ms as number | undefined;
        const dangerCheck = checkDangerousCommand(command);
        if (dangerCheck.isDangerous) {
          const confirmId = generateId();
          pendingConfirmations.set(confirmId, {
            id: confirmId,
            command,
            reason: dangerCheck.reasons.join(", "),
            createdAt: new Date(),
          });
          addLog("warning", `Dangerous command requires confirmation: ${command}`);
          return {
            content: [{
              type: "text",
              text:
                `⚠️ DANGEROUS COMMAND REQUIRES CONFIRMATION\n\n` +
                `Command: ${command}\nReasons: ${dangerCheck.reasons.join(", ")}\n\n` +
                `ssh_execute_dangerous { confirmation_id: "${confirmId}", confirm: true }`,
            }],
          };
        }
        const result = await sshExecute(command, timeoutMs);
        return { content: [{ type: "text", text: result }] };
      }

      case "ssh_execute_dangerous": {
        const confirmId = args?.confirmation_id as string;
        const confirm = args?.confirm as boolean;
        const pending = pendingConfirmations.get(confirmId);
        if (!pending) return { content: [{ type: "text", text: `❌ Confirmation "${confirmId}" not found or expired` }] };
        pendingConfirmations.delete(confirmId);
        if (!confirm) {
          addLog("info", `Command cancelled: ${pending.command}`);
          return { content: [{ type: "text", text: `✅ Cancelled: ${pending.command}` }] };
        }
        addLog("warning", `Dangerous command confirmed: ${pending.command}`);
        const result = await sshExecute(pending.command);
        return { content: [{ type: "text", text: result }] };
      }

      case "ssh_execute_background": {
        const command = args?.command as string;
        const { id } = await sshExecuteBackground(command);
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

      case "ssh_read_background":
        return { content: [{ type: "text", text: readBackgroundJob(args?.job_id as string, args?.tail as number | undefined) }] };

      case "ssh_kill_background":
        return { content: [{ type: "text", text: await killBackgroundJob(args?.job_id as string) }] };

      case "ssh_list_background":
        return { content: [{ type: "text", text: listBackgroundJobs() }] };

      case "ssh_write_file":
        return { content: [{ type: "text", text: await sshUploadFile(args?.content as string, args?.remote_path as string) }] };

      case "ssh_read_file":
        return { content: [{ type: "text", text: await sshReadFile(args?.remote_path as string) }] };

      case "ssh_list_dir":
        return { content: [{ type: "text", text: await sshListDir((args?.remote_path as string) || ".") }] };

      case "ssh_download_file": {
        const result = await sshDownloadFile(args?.remote_path as string, (args?.as_base64 as boolean) || false);
        const output = [
          `✅ File downloaded to temp store`,
          ``,
          `📋 Info:`,
          `  ID: ${result.tempFile.id}`,
          `  File: ${result.tempFile.filename}`,
          `  Size: ${formatBytes(result.tempFile.size)}`,
          `  Type: ${result.tempFile.isBinary ? "binary" : "text"}`,
          `  Local: ${result.tempFile.localPath}`,
          `  Remote: ${result.tempFile.remotePath}`,
          ``,
          `📝 Content:`,
          `─────────────────────────────────────`,
          result.preview,
        ].join("\n");
        return { content: [{ type: "text", text: output }] };
      }

      case "ssh_temp_list": {
        const files = listTempFiles();
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
        const tempFile = getTempFile(tempId);
        if (!tempFile) return { content: [{ type: "text", text: `❌ Temp "${tempId}" not found` }] };
        const content = readTempFileContent(tempId);
        if (!content) return { content: [{ type: "text", text: `❌ Failed to read` }] };
        const output = asBase64 || tempFile.isBinary ? content.toString("base64") : content.toString("utf-8");
        return { content: [{ type: "text", text: output }] };
      }

      case "ssh_temp_write": {
        const tempId = args?.temp_id as string;
        const contentStr = args?.content as string;
        const isBase64 = (args?.is_base64 as boolean) || false;
        const tempFile = getTempFile(tempId);
        if (!tempFile) return { content: [{ type: "text", text: `❌ Temp "${tempId}" not found` }] };
        const content = isBase64 ? Buffer.from(contentStr, "base64") : Buffer.from(contentStr, "utf-8");
        if (updateTempFile(tempId, content)) {
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
        return { content: [{ type: "text", text: await sshUploadFromTemp(args?.temp_id as string, args?.remote_path as string | undefined) }] };

      case "ssh_temp_delete": {
        const ok = deleteTempFile(args?.temp_id as string);
        return { content: [{ type: "text", text: ok ? "✅ Removed" : "❌ Not found" }] };
      }

      case "ssh_temp_cleanup": {
        const count = cleanupAllTempFiles();
        return { content: [{ type: "text", text: `✅ Removed: ${count}` }] };
      }

      case "ssh_temp_path": {
        const tempFile = getTempFile(args?.temp_id as string);
        if (!tempFile) return { content: [{ type: "text", text: `❌ Not found` }] };
        return { content: [{ type: "text", text: `📄 ${tempFile.localPath}` }] };
      }

      case "ssh_file_info":
        return { content: [{ type: "text", text: await sshFileInfo(args?.remote_path as string) }] };

      case "ssh_mkdir":
        return { content: [{ type: "text", text: await sshMkdir(args?.remote_path as string, (args?.recursive as boolean) || false) }] };

      case "ssh_rename":
        return { content: [{ type: "text", text: await sshRename(args?.old_path as string, args?.new_path as string) }] };

      case "ssh_copy":
        return { content: [{ type: "text", text: await sshCopy(args?.src_path as string, args?.dest_path as string) }] };

      case "ssh_chmod":
        return { content: [{ type: "text", text: await sshChmod(args?.remote_path as string, args?.mode as string) }] };

      case "ssh_delete": {
        const remotePath = args?.remote_path as string;
        const isDirectory = (args?.is_directory as boolean) || false;
        const confirmId = generateId();
        pendingDeleteConfirmations.set(confirmId, {
          id: confirmId,
          path: remotePath,
          isDirectory,
          createdAt: new Date(),
        });
        addLog("warning", `Deletion requires confirmation: ${remotePath}`);
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
        const confirmId = args?.confirmation_id as string;
        const confirm = args?.confirm as boolean;
        const pending = pendingDeleteConfirmations.get(confirmId);
        if (!pending) return { content: [{ type: "text", text: `❌ Confirmation "${confirmId}" not found or expired` }] };
        pendingDeleteConfirmations.delete(confirmId);
        if (!confirm) {
          addLog("info", `Deletion cancelled: ${pending.path}`);
          return { content: [{ type: "text", text: `✅ Cancelled: ${pending.path}` }] };
        }
        addLog("warning", `Deletion confirmed: ${pending.path}`);
        return { content: [{ type: "text", text: await sshDelete(pending.path, pending.isDirectory) }] };
      }

      case "ssh_get_logs": {
        const limit = args?.limit as number | undefined;
        if (!state.session) return { content: [{ type: "text", text: "No active session." }] };
        const logs = formatLogs(state.session.logs, limit);
        return { content: [{ type: "text", text: logs || "No log entries yet" }] };
      }

      case "ssh_status": {
        if (!state.session) return { content: [{ type: "text", text: "❌ No active connection" }] };
        const duration = Math.round((Date.now() - state.session.startTime.getTime()) / 1000);
        const status = state.session.connected ? "🟢 Connected" : "🔴 Disconnected";
        const proxyLine = state.session.proxyUsed
          ? `\nProxy: ${describeProxy(state.session.proxyUsed)}`
          : "\nProxy: direct";
        return {
          content: [{
            type: "text",
            text:
              `${status}\nHost: ${state.session.config.host}:${state.session.config.port || 22}\n` +
              `User: ${state.session.config.username}\nSession time: ${duration}s\n` +
              `Log entries: ${state.session.logs.length}${proxyLine}`,
          }],
        };
      }

      case "ssh_disconnect":
        return { content: [{ type: "text", text: sshDisconnect((args?.cleanup_temp as boolean) || false) }] };

      case "ssh_pending_confirmations": {
        if (pendingConfirmations.size === 0) return { content: [{ type: "text", text: "No pending confirmations" }] };
        const list = Array.from(pendingConfirmations.values())
          .map((p) => `ID: ${p.id}\nCommand: ${p.command}\nReason: ${p.reason}`)
          .join("\n\n");
        return { content: [{ type: "text", text: list }] };
      }

      case "ssh_upload":
        return {
          content: [{
            type: "text",
            text: await sshUpload(
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
    addLog("error", message);
    return { content: [{ type: "text", text: `❌ Error: ${message}` }], isError: true };
  }
}
