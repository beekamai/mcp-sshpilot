export const TOOL_DEFINITIONS = [
  {
    name: "ssh_connect",
    description:
      "Connect over SSH with explicit parameters. If `proxy` is provided, the connection goes through it. Otherwise the runtime override / global config proxy is applied (see ssh_proxy_status).",
    inputSchema: {
      type: "object",
      properties: {
        host: { type: "string" },
        port: { type: "number", description: "Defaults to 22" },
        username: { type: "string" },
        password: { type: "string" },
        privateKey: { type: "string", description: "Private key contents" },
        passphrase: { type: "string" },
        proxy: {
          type: "object",
          description: "Optional proxy for this connection (overrides runtime override and global config)",
          properties: {
            type: { type: "string", enum: ["socks4", "socks5", "http", "https"] },
            host: { type: "string" },
            port: { type: "number" },
            username: { type: "string" },
            password: { type: "string" },
          },
          required: ["type", "host", "port"],
        },
      },
      required: ["host", "username"],
    },
  },
  {
    name: "ssh_connect_profile",
    description:
      "Connect using a saved profile from servers.json. The AI does NOT see credentials — only the profile name. Proxy precedence: runtime override → server.proxy → config.proxy. server.proxy=null forces direct connection for this server. The server's host key is pinned on the first connect (trust on first use); a different key is refused. On a mismatch, stop and tell the user: never re-pin a key you cannot verify yourself.",
    inputSchema: {
      type: "object",
      properties: { profile_name: { type: "string" } },
      required: ["profile_name"],
    },
  },
  {
    name: "ssh_list_profiles",
    description: "List server profiles (no secrets). Shows the active proxy for each.",
    inputSchema: { type: "object", properties: {} },
  },

  {
    name: "ssh_server_add",
    description:
      "Add a new profile to servers.json. Returns an error if a profile with the same name exists (use ssh_server_update).",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string" },
        host: { type: "string" },
        port: { type: "number" },
        username: { type: "string" },
        password: { type: "string" },
        privateKeyPath: { type: "string" },
        passphrase: { type: "string" },
        description: { type: "string" },
        proxy: {
          type: ["object", "null"],
          description: "Per-server proxy. null forces direct, overriding the global proxy.",
          properties: {
            type: { type: "string", enum: ["socks4", "socks5", "http", "https"] },
            host: { type: "string" },
            port: { type: "number" },
            username: { type: "string" },
            password: { type: "string" },
          },
        },
      },
      required: ["name", "host", "username"],
    },
  },
  {
    name: "ssh_server_update",
    description:
      "Update an existing profile. Only fields you pass are changed. proxy:null → force direct; proxy:false → drop the field entirely; proxy:object → set it. Changing host/port/username/proxy keeps the pinned host key, so the new route must lead to a server with the same key; a live session keeps verifying against the key it connected with.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Existing profile name" },
        host: { type: "string" },
        port: { type: "number" },
        username: { type: "string" },
        password: { type: "string" },
        privateKeyPath: { type: "string" },
        passphrase: { type: "string" },
        description: { type: "string" },
        rename_to: { type: "string", description: "New profile name" },
        proxy: { description: "object | null | false" },
        reset_host_key: {
          type: "boolean",
          description:
            "Drop the pinned host key; the next ssh_connect_profile pins the key the server presents. Only after the user verified the new key on the server itself.",
        },
      },
      required: ["name"],
    },
  },
  {
    name: "ssh_server_remove",
    description: "Remove a profile from servers.json by name.",
    inputSchema: {
      type: "object",
      properties: { name: { type: "string" } },
      required: ["name"],
    },
  },

  {
    name: "ssh_proxy_status",
    description: "Current proxy state: global from config, runtime override, and what will be applied.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "ssh_proxy_set",
    description:
      "Set a proxy. scope='runtime' (default) for the lifetime of the process; scope='global' writes it into servers.json as the global proxy.",
    inputSchema: {
      type: "object",
      properties: {
        type: { type: "string", enum: ["socks4", "socks5", "http", "https"] },
        host: { type: "string" },
        port: { type: "number" },
        username: { type: "string" },
        password: { type: "string" },
        scope: { type: "string", enum: ["runtime", "global"] },
      },
      required: ["type", "host", "port"],
    },
  },
  {
    name: "ssh_proxy_disable",
    description:
      "Disable proxy. scope='runtime' (default) — no proxy applied to any connection until ssh_proxy_enable. scope='global' — remove the global proxy from servers.json.",
    inputSchema: {
      type: "object",
      properties: { scope: { type: "string", enum: ["runtime", "global"] } },
    },
  },
  {
    name: "ssh_proxy_enable",
    description: "Clear the runtime override and fall back to config settings.",
    inputSchema: { type: "object", properties: {} },
  },

  {
    name: "ssh_execute",
    description:
      "Execute a command. Dangerous commands require confirmation. Hard timeout (default 5 min): if the command forks a background process inheriting stdout, the channel will not close and you will receive partial output. For long-running/daemon commands use ssh_execute_background, or redirect descriptors: `cmd > /dev/null 2>&1 < /dev/null & disown`.",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string" },
        timeout_ms: { type: "number", description: "Timeout in ms (default 300000)" },
      },
      required: ["command"],
    },
  },
  {
    name: "ssh_execute_dangerous",
    description: "Confirm or cancel a dangerous command via confirmation_id.",
    inputSchema: {
      type: "object",
      properties: {
        confirmation_id: { type: "string" },
        confirm: { type: "boolean" },
      },
      required: ["confirmation_id", "confirm"],
    },
  },
  {
    name: "ssh_execute_background",
    description:
      "Run a long-running command in the background. Returns job_id immediately. Stdout/stderr are buffered up to 256KB. Use ssh_read_background to read, ssh_kill_background to stop.",
    inputSchema: {
      type: "object",
      properties: { command: { type: "string" } },
      required: ["command"],
    },
  },
  {
    name: "ssh_read_background",
    description: "Read accumulated stdout/stderr of a background job and its status.",
    inputSchema: {
      type: "object",
      properties: {
        job_id: { type: "string" },
        tail: { type: "number", description: "Last N bytes of each stream" },
      },
      required: ["job_id"],
    },
  },
  {
    name: "ssh_kill_background",
    description: "Stop a background job (close channel, send SIGKILL if supported).",
    inputSchema: {
      type: "object",
      properties: { job_id: { type: "string" } },
      required: ["job_id"],
    },
  },
  {
    name: "ssh_list_background",
    description: "List all background jobs (id, status, elapsed, command).",
    inputSchema: { type: "object", properties: {} },
  },

  {
    name: "ssh_write_file",
    description: "Write content to a file on the server (overwrites if exists).",
    inputSchema: {
      type: "object",
      properties: {
        remote_path: { type: "string" },
        content: { type: "string" },
      },
      required: ["remote_path", "content"],
    },
  },
  {
    name: "ssh_read_file",
    description: "Read file contents from the server.",
    inputSchema: {
      type: "object",
      properties: { remote_path: { type: "string" } },
      required: ["remote_path"],
    },
  },
  {
    name: "ssh_list_dir",
    description: "List directory contents on the server.",
    inputSchema: {
      type: "object",
      properties: { remote_path: { type: "string" } },
      required: ["remote_path"],
    },
  },
  {
    name: "ssh_download_file",
    description: "Download a file. Binary files → base64. Saved to the temp store; an ID is returned for editing.",
    inputSchema: {
      type: "object",
      properties: {
        remote_path: { type: "string" },
        as_base64: { type: "boolean" },
      },
      required: ["remote_path"],
    },
  },
  { name: "ssh_temp_list", description: "List downloaded temp files.", inputSchema: { type: "object", properties: {} } },
  {
    name: "ssh_temp_read",
    description: "Read a temp file by ID.",
    inputSchema: {
      type: "object",
      properties: { temp_id: { type: "string" }, as_base64: { type: "boolean" } },
      required: ["temp_id"],
    },
  },
  {
    name: "ssh_temp_write",
    description: "Write new content to a temp file.",
    inputSchema: {
      type: "object",
      properties: {
        temp_id: { type: "string" },
        content: { type: "string" },
        is_base64: { type: "boolean" },
      },
      required: ["temp_id", "content"],
    },
  },
  {
    name: "ssh_temp_upload",
    description: "Upload a temp file to the server.",
    inputSchema: {
      type: "object",
      properties: {
        temp_id: { type: "string" },
        remote_path: { type: "string" },
      },
      required: ["temp_id"],
    },
  },
  {
    name: "ssh_temp_delete",
    description: "Delete a temp file.",
    inputSchema: {
      type: "object",
      properties: { temp_id: { type: "string" } },
      required: ["temp_id"],
    },
  },
  { name: "ssh_temp_cleanup", description: "Delete all temp files.", inputSchema: { type: "object", properties: {} } },
  {
    name: "ssh_temp_path",
    description: "Local path to a temp file.",
    inputSchema: {
      type: "object",
      properties: { temp_id: { type: "string" } },
      required: ["temp_id"],
    },
  },
  {
    name: "ssh_file_info",
    description: "Stat a file/directory.",
    inputSchema: {
      type: "object",
      properties: { remote_path: { type: "string" } },
      required: ["remote_path"],
    },
  },
  {
    name: "ssh_mkdir",
    description: "Create a directory.",
    inputSchema: {
      type: "object",
      properties: {
        remote_path: { type: "string" },
        recursive: { type: "boolean" },
      },
      required: ["remote_path"],
    },
  },
  {
    name: "ssh_rename",
    description: "Rename or move.",
    inputSchema: {
      type: "object",
      properties: {
        old_path: { type: "string" },
        new_path: { type: "string" },
      },
      required: ["old_path", "new_path"],
    },
  },
  {
    name: "ssh_copy",
    description: "Copy on the server (cp -r).",
    inputSchema: {
      type: "object",
      properties: {
        src_path: { type: "string" },
        dest_path: { type: "string" },
      },
      required: ["src_path", "dest_path"],
    },
  },
  {
    name: "ssh_chmod",
    description: "chmod (octal: 755, 644, ...).",
    inputSchema: {
      type: "object",
      properties: {
        remote_path: { type: "string" },
        mode: { type: "string" },
      },
      required: ["remote_path", "mode"],
    },
  },
  {
    name: "ssh_delete",
    description: "Delete a file or empty directory (requires confirmation).",
    inputSchema: {
      type: "object",
      properties: {
        remote_path: { type: "string" },
        is_directory: { type: "boolean" },
      },
      required: ["remote_path"],
    },
  },
  {
    name: "ssh_delete_confirm",
    description: "Confirm or cancel deletion via confirmation_id.",
    inputSchema: {
      type: "object",
      properties: {
        confirmation_id: { type: "string" },
        confirm: { type: "boolean" },
      },
      required: ["confirmation_id", "confirm"],
    },
  },

  {
    name: "ssh_get_logs",
    description: "Current session logs.",
    inputSchema: { type: "object", properties: { limit: { type: "number" } } },
  },
  {
    name: "ssh_status",
    description: "Connection status (including proxy used).",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "ssh_disconnect",
    description: "Disconnect from the server.",
    inputSchema: {
      type: "object",
      properties: { cleanup_temp: { type: "boolean" } },
    },
  },
  {
    name: "ssh_pending_confirmations",
    description: "List dangerous commands awaiting confirmation.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "ssh_upload",
    description:
      "Upload a file/directory. Files → SFTP. Directories → tar.gz, upload, extract on the server.",
    inputSchema: {
      type: "object",
      properties: {
        local_path: { type: "string" },
        remote_path: { type: "string" },
        exclude: { type: "array", items: { type: "string" } },
      },
      required: ["local_path", "remote_path"],
    },
  },
];

/* Remote mode: the MCP host is a shared server, not the agent's machine. Its filesystem is off limits, and
 * raw credentials typed by the model are refused so every connection goes through a saved (pinned) profile. */
const REMOTE_DISABLED_TOOLS = new Set(["ssh_upload", "ssh_temp_path", "ssh_connect"]);

/* Profiles in the vault carry the key inline; a key path would point into the server's own filesystem. Host-key
 * pins are re-set only by the owner out of band (vault pin-host-key), never by the model. */
const REMOTE_KEY_PROPERTY = {
  type: "string",
  description: "Private key contents (PEM/OpenSSH). Stored encrypted in the vault; never returned by any tool.",
};

/* Connector grants are read-only snapshots: the only store write they keep is a first-use host-key pin, and the
 * proxy tools would let the model reroute (or unpin-gate) a granted profile. */
const SCOPED_DISABLED_TOOLS = new Set([
  "ssh_server_add",
  "ssh_server_update",
  "ssh_server_remove",
  "ssh_proxy_set",
  "ssh_proxy_enable",
  "ssh_proxy_disable",
]);

type ToolDefinition = (typeof TOOL_DEFINITIONS)[number];

export function isToolAvailable(mode: "stdio" | "remote", name: string, scoped = false): boolean {
  if (scoped && SCOPED_DISABLED_TOOLS.has(name)) return false;
  return mode !== "remote" || !REMOTE_DISABLED_TOOLS.has(name);
}

function toRemote(def: ToolDefinition): ToolDefinition {
  const description = def.description.replace(/servers\.json/g, "the vault");
  if (def.name !== "ssh_server_add" && def.name !== "ssh_server_update") return { ...def, description };
  const { privateKeyPath: _dropped, reset_host_key: _owner, ...properties } = (def.inputSchema as any).properties;
  return {
    ...def,
    description:
      def.name === "ssh_server_update"
        ? description + " On a profile without a pinned host key, a route change removes the stored password unless a new one is passed."
        : description,
    inputSchema: { ...def.inputSchema, properties: { ...properties, privateKey: REMOTE_KEY_PROPERTY } },
  } as ToolDefinition;
}

/** Tool definitions a client in the given mode may see and call. */
export function listToolsFor(mode: "stdio" | "remote", scoped = false): ToolDefinition[] {
  if (mode !== "remote") return TOOL_DEFINITIONS;
  return TOOL_DEFINITIONS.filter((d) => isToolAvailable(mode, d.name, scoped)).map(toRemote);
}
