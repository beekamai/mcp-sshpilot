# mcp-sshpilot

[![npm version](https://img.shields.io/npm/v/mcp-sshpilot.svg)](https://www.npmjs.com/package/mcp-sshpilot)
[![npm downloads](https://img.shields.io/npm/dm/mcp-sshpilot.svg)](https://www.npmjs.com/package/mcp-sshpilot)
[![node](https://img.shields.io/node/v/mcp-sshpilot.svg)](https://nodejs.org)
[![license](https://img.shields.io/npm/l/mcp-sshpilot.svg)](./LICENSE)

> 🇬🇧 [English](#english) · 🇷🇺 [Русский](#русский)

---

## English

MCP server for managing remote machines over SSH from Cursor / Claude Code / Claude Desktop / any MCP client.

### Quick start

#### Step 1 — install globally

```bash
npm i -g mcp-sshpilot
```

#### Step 2 — add to your MCP client

**Claude Code (CLI):**

```bash
# available in every project:
claude mcp add sshpilot --scope user mcp-sshpilot

# this project only (writes to ./.mcp.json):
claude mcp add sshpilot mcp-sshpilot
```

Verify: `claude mcp list` → `sshpilot: mcp-sshpilot — ✓ Connected`

**Other clients** — add to the config file and restart:

```json
{
  "mcpServers": {
    "sshpilot": {
      "command": "mcp-sshpilot",
      "args": []
    }
  }
}
```

| Client | Config path |
|---|---|
| **Cursor** (global) | `~/.cursor/mcp.json` |
| **Cursor** (per-project) | `<project>/.cursor/mcp.json` |
| **Claude Desktop** (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| **Claude Desktop** (Windows) | `%APPDATA%\Claude\claude_desktop_config.json` |
| **Windsurf / Cline / others** | check the client's MCP docs — same JSON format |

#### Step 3 — first launch

On first launch the server creates an empty config at `~/.config/mcp-sshpilot/servers.json` (`%USERPROFILE%\.config\mcp-sshpilot\servers.json` on Windows). Add a profile via the `ssh_server_add` tool, or edit the JSON directly using [`servers.example.json`](./servers.example.json) as a template.

#### Updating

```bash
npm i -g mcp-sshpilot@latest
```

> **Why not `npx`?** MCP clients spawn the server on every session start and enforce a startup timeout. `npx` checks the npm registry on each run (~3–5 s latency), which can exceed that timeout causing the server to appear "not connected" — especially in new tabs or fresh windows. A global install starts in milliseconds.

### Features

- 🔐 **Server profiles** — the AI works by name and never sees passwords/keys
- 🌐 **Proxy** — SOCKS4 / SOCKS5 / HTTP / HTTPS CONNECT, global or per-server, with runtime override
- 🛡️ **Dangerous-command guard** — `rm -rf`, `DROP TABLE`, `shutdown`, `chmod 777` etc. require explicit confirmation
- 📁 **SFTP** — read / write / list / stat / mkdir / rename / chmod / copy / delete
- 📦 **Bulk upload** — directories as tar.gz with extraction on the server
- ⏳ **Background jobs** — for long-running / daemon-like commands
- ⚙️ **Profile CRUD by the agent** — `ssh_server_add` / `update` / `remove`
- 📜 **Full session log** + `ssh://logs` resource
- 🔏 **Host key pinning** — the first connect pins the server's key (TOFU); a different key is refused before any credential is sent
- 🌍 **Remote mode** — one HTTPS server with an encrypted profile vault for agents on several devices ([Remote mode](#remote-mode))

### Install (alternatives)

#### `npx` (no pre-install, slower start)

If you can't or don't want to install globally, `npx` works as a fallback — but read the warning in [Quick start](#quick-start) about startup latency.

```json
{
  "mcpServers": {
    "sshpilot": {
      "command": "npx",
      "args": ["-y", "mcp-sshpilot"]
    }
  }
}
```

#### From source (for hacking on the code)

```bash
git clone https://github.com/beekamai/mcp-sshpilot.git
cd mcp-sshpilot
npm install
npm run build
```

```json
{
  "mcpServers": {
    "sshpilot": {
      "command": "node",
      "args": ["C:/path/to/mcp-sshpilot/dist/index.js"]
    }
  }
}
```

For live development without rebuild:

```json
{
  "mcpServers": {
    "sshpilot": {
      "command": "npx",
      "args": ["tsx", "C:/path/to/mcp-sshpilot/src/index.ts"]
    }
  }
}
```

### Server config

The config is auto-created on first launch. Path resolution (first match wins):

1. `MCP_SSHPILOT_CONFIG` env var — explicit path (supports `~/...`)
2. `<install_root>/servers.json` — only meaningful when running **from source** (next to `dist/`). For `npx`/global installs this lives inside the npm cache and rarely matches.
3. `~/.config/mcp-sshpilot/servers.json` — **default for `npx` / `npm i -g`**. On Windows: `%USERPROFILE%\.config\mcp-sshpilot\servers.json`.

Manage profiles via the `ssh_server_add` / `update` / `remove` tools, or edit the JSON directly:

```json
{
  "proxy": {
    "type": "socks5",
    "host": "127.0.0.1",
    "port": 1080
  },
  "servers": [
    {
      "name": "production",
      "host": "10.0.0.1",
      "port": 22,
      "username": "root",
      "password": "secret",
      "description": "uses the global socks5"
    },
    {
      "name": "staging",
      "host": "staging.example.com",
      "username": "deploy",
      "privateKeyPath": "~/.ssh/id_rsa",
      "passphrase": "...",
      "proxy": null,
      "description": "direct, overrides the global proxy"
    },
    {
      "name": "corp",
      "host": "10.1.2.3",
      "username": "ops",
      "privateKeyPath": "D:/keys/ops.pem",
      "proxy": {
        "type": "http",
        "host": "proxy.corp.local",
        "port": 8080,
        "username": "user",
        "password": "pass"
      }
    }
  ]
}
```

### Proxy precedence

Order: **runtime override → `server.proxy` → `config.proxy`**.

| Setting | Behaviour |
|---|---|
| `ssh_proxy_disable` | direct, everywhere, until `ssh_proxy_enable` |
| `ssh_proxy_set` (runtime) | this proxy for all connections |
| `server.proxy: null` | direct for this server even if a global one is set |
| `server.proxy: {...}` | per-server proxy |
| `config.proxy: {...}` | default for servers without their own |

The AI **never sees proxy passwords** in `ssh_proxy_status` — only `type://user@host:port`.

### Tools (for the AI)

**Several connections at once.** One session holds up to 16 connections (remote mode: 4 per session), named
after their profile (case-insensitive) or `user@host:port` for `ssh_connect`, so parallel subagents of one client
neither block nor retarget each other. Every tool that acts on a server takes an optional `profile`: given, that
connection is used, and a saved profile that is not connected yet is connected first (same pin checks as
`ssh_connect_profile`); omitted, the only open connection is used. With several open and no `profile`, the call is
refused and nothing runs. Confirmations, background jobs and temp files stay bound to the connection they came from:
`ssh_execute_dangerous` / `ssh_delete_confirm` always run there, `ssh_temp_upload` without `profile` goes back there.

#### Connection / profiles

| Tool | Description |
|---|---|
| `ssh_connect` | Direct connect with explicit params (+ optional `proxy`); the connection is named `user@host:port` |
| `ssh_connect_profile` | Connect by profile name. AI does not see credentials. Optional: a tool called with `profile` connects it on first use |
| `ssh_list_profiles` | Profile list with description and active proxy |
| `ssh_status` | Status of every open connection, incl. proxy used and host key (`profile` shows one) |
| `ssh_disconnect` | `profile` closes one, `all: true` closes all; without either only when exactly one is open. `cleanup_temp` removes its temp files |
| `ssh_pin_host_keys` | Pin host keys without credentials: key exchange only, aborted before authentication. Default: every unpinned profile; never overwrites a pin (stdio only) |

#### Server CRUD

| Tool | Description |
|---|---|
| `ssh_server_add` | Add a profile to `servers.json` |
| `ssh_server_update` | Update fields (with `rename_to`). `proxy:null` forces direct, `proxy:false` removes the field. `reset_host_key:true` drops the pinned host key (stdio only; remote: `vault pin-host-key`) |
| `ssh_server_remove` | Remove a profile by name |

#### Proxy management

| Tool | Description |
|---|---|
| `ssh_proxy_status` | Global + override + currently applied |
| `ssh_proxy_set` | Set proxy. `scope: runtime` (default) or `global` (write to `servers.json`) |
| `ssh_proxy_disable` | Disable proxy. `scope: runtime` (default) or `global` (remove from config) |
| `ssh_proxy_enable` | Clear runtime override, fall back to config |

#### Command execution

| Tool | Description |
|---|---|
| `ssh_execute` | Run a command. A non-zero exit is reported as `[exit code: N]` at the end of the output. Hard timeout `timeout_ms` (default 300000). For long-running / daemon-like commands use `ssh_execute_background` instead, or detach descriptors: `cmd > /dev/null 2>&1 < /dev/null & disown` |
| `ssh_execute_dangerous` | Confirm/cancel via `confirmation_id` |
| `ssh_execute_background` | Run in background, returns `job_id` |
| `ssh_read_background` | Read stdout/stderr/status |
| `ssh_kill_background` | Kill a background job (SIGKILL, close channel) |
| `ssh_list_background` | List all jobs with their connection (`profile` filters) |
| `ssh_pending_confirmations` | List awaiting confirmations |

#### Files / SFTP

| Tool | Description |
|---|---|
| `ssh_read_file` / `ssh_write_file` | Text files directly |
| `ssh_list_dir` | `ls` of a directory |
| `ssh_file_info` | stat (size, mode, owner, mtime) |
| `ssh_mkdir` (recursive) / `ssh_rename` / `ssh_chmod` / `ssh_copy` | Standard ops |
| `ssh_delete` + `ssh_delete_confirm` | Delete with confirmation |
| `ssh_download_file` | Download to temp store, return preview + ID; `as_base64: true` returns the whole file inline as base64 up to 2 MiB |
| `ssh_temp_list` / `read` / `write` / `upload` / `delete` / `cleanup` / `path` | Temp store (edit before re-upload) |
| `ssh_upload` | File → SFTP. Directory → tar.gz + upload + extract (`exclude` patterns supported) |

#### Logs

| Tool | Description |
|---|---|
| `ssh_get_logs` | Log of all connections, entries tagged `[name]`. `limit` — last N, `profile` — one connection |

The MCP resource `ssh://logs` is also exposed.

### Remote mode

Run one server on a box you control and let several agents on different devices share the same profiles over HTTPS:

```bash
export MCP_SSHPILOT_VAULT=./vault.json
mcp-sshpilot vault init --import ~/.config/mcp-sshpilot/servers.json --out recovery.token   # keep it offline
mcp-sshpilot vault add-device laptop --out laptop.token   # unlock key from $MCP_SSHPILOT_UNLOCK_KEY or stdin
mcp-sshpilot serve                                        # 127.0.0.1:8722, put TLS in front (deploy/ has Docker + Caddy)

claude mcp add --transport http --scope user sshpilot https://mcp.example.com/mcp \
  --header "Authorization: Bearer <device token>"
```

- Profiles live in an AES-256-GCM vault; the server stores no key that opens it. A device token unlocks it for that device's session only.
- One token per device, revocable at once (`vault revoke-device`); sessions are isolated per device.
- Plain HTTP off loopback is refused unless forced; browser origins are blocked by default; failed auth is rate limited.
- Tools that touch the server's own filesystem (`ssh_upload`, `ssh_temp_path`) and raw `ssh_connect` are disabled remotely.
- Host keys are re-pinned only by the owner (`vault pin-host-key`), never by the model; `vault rotate` also replaces the recovery key.

**Claude connectors (web/mobile):** with `serve --oauth --public-url https://mcp.example.com` the server also speaks
the MCP OAuth flow. When you add it as a custom connector, a consent page on your own server asks for a device token
and lets you tick exactly which profiles that connector may use; it gets its own encrypted copy of those profiles
only, can't change them, and is revoked with `vault revoke-grant` (or together with the device that approved it,
`vault revoke-device`). Approve only a connection you started yourself a moment ago.

Setup, threat model, revocation limits and the Docker deployment: **[docs/remote.md](./docs/remote.md)**.

### Security & secret hygiene

- `servers.json` is in `.gitignore` — **don't commit credentials**.
- Dangerous commands (full list below) are auto-blocked and require `ssh_execute_dangerous` with `confirm: true`. `ssh_delete` also requires confirmation. The same check applies to `ssh_execute_background`. A confirmation is bound to the connection it was issued in and expires after 10 minutes — it is refused after switching servers or reconnecting.
- The AI sees only the profile name, host:port, description, and `type://user@host:port` proxy — never passwords or private keys.

#### Block agents from reading `servers.json`

The MCP protocol itself has no per-file ACL — `mcp-sshpilot` never returns the file's content to the model, but the agent's *generic* file tools (Read/Grep/Glob in Claude Code, file-search in Cursor, etc.) can still open it. Add an explicit rule. **Recommended snippet:**

```md
## Secrets policy

- NEVER read, open, grep, glob, cat, copy, attach, or otherwise access `servers.json`
  in this repository. It contains plaintext SSH credentials for `mcp-sshpilot`.
- If you need server info, call the `ssh_list_profiles` MCP tool — it returns a
  redacted view (name, host:port, description, proxy summary) without secrets.
- Treat `servers.json` as if it does not exist on the filesystem.
```

| Agent | Where to put the rule |
|---|---|
| **Claude Code** | `CLAUDE.md` at project root. Optionally add `Read(./servers.json)` to `permissions.deny` in `.claude/settings.json` |
| **OpenAI Codex CLI / ChatGPT Codex** | `AGENTS.md` at project root |
| **Cursor** | `.cursor/rules/secrets.mdc` (Project Rules) — `alwaysApply: true` |
| **Windsurf** | `.windsurfrules` at project root |
| **GitHub Copilot Chat / Workspace** | `.github/copilot-instructions.md` |
| **Cline / Roo Code** | `.clinerules` at project root |

Belt-and-suspenders: keep `servers.json` outside the workspace entirely (option 3 in [Server config](#server-config)) — then no agent tool can reach it regardless of rules.

#### Dangerous patterns

Removal (`rm -rf`, `rmdir`), formatting (`mkfs`, `dd if=`, `fdisk`, `parted`), system (`shutdown`, `reboot`, `init 0/6`), services (`systemctl stop/disable/mask`, `service stop`), permissions (world-writable `chmod`: `777`, `666`, `o+w`; `chown -R`, `userdel`, `groupdel`), network (`iptables -F`, `ufw disable`), packages (`apt remove/purge/autoremove`, `yum/dnf remove/erase`), DB (`DROP DATABASE/TABLE/USER`, `TRUNCATE`, `DELETE FROM`), Docker (`docker rm/rmi`, `system prune`, `docker compose` / `docker-compose` `down/rm`, `docker volume/network/image/container rm/prune`), processes (`kill -9`, `killall`, `pkill`), pipes into shell.

<details>
<summary>Project layout</summary>

```
src/
  index.ts       — entrypoint: CLI dispatch, stdio server
  cli.ts         — `vault ...` and `serve` commands
  mcp-server.ts  — builds one MCP Server per session ctx (tools, ssh://logs)
  http.ts        — remote mode: Streamable HTTP, auth, sessions, limits, audit
  oauth.ts       — OAuth for Claude connectors: discovery, registration, consent, tokens
  consent.ts     — HTML of the consent pages
  vault.ts       — encrypted profile vault, device tokens, connector grants
  types.ts       — shared types
  state.ts       — per-session state (SessionCtx) and its teardown
  utils.ts       — id, byte/perm/log formatters
  danger.ts      — patterns + checkDangerousCommand
  config.ts      — ProfileStore, servers.json store, profileToConnectConfig
  proxy.ts       — validate/describe/resolve + buildProxySocket + HTTP CONNECT
  ssh-core.ts    — connect/disconnect/execute, host key pinning, background jobs
  ssh-fs.ts      — SFTP ops + bulk upload (tar.gz)
  temp.ts        — temp file store (per-session quota in remote mode)
  tools.ts       — MCP tool definitions, remote-mode filtering
  handlers.ts    — tool call dispatcher
test/            — node:test suites (npm test)
deploy/          — Dockerfile, docker-compose.yml, Caddyfile
docs/remote.md   — remote mode guide and threat model
```

</details>

### License

MIT

---

## Русский

MCP-сервер для управления удалёнными машинами по SSH из Cursor / Claude Code / Claude Desktop / любого MCP-клиента.

### Быстрый старт

#### Шаг 1 — глобальная установка

```bash
npm i -g mcp-sshpilot
```

#### Шаг 2 — добавить в MCP-клиент

**Claude Code (CLI):**

```bash
# во всех проектах:
claude mcp add sshpilot --scope user mcp-sshpilot

# только в этом проекте (пишется в ./.mcp.json):
claude mcp add sshpilot mcp-sshpilot
```

Проверка: `claude mcp list` → `sshpilot: mcp-sshpilot — ✓ Connected`

**Другие клиенты** — добавь в конфиг и перезапусти:

```json
{
  "mcpServers": {
    "sshpilot": {
      "command": "mcp-sshpilot",
      "args": []
    }
  }
}
```

| Клиент | Путь к конфигу |
|---|---|
| **Cursor** (глобально) | `~/.cursor/mcp.json` |
| **Cursor** (per-project) | `<project>/.cursor/mcp.json` |
| **Claude Desktop** (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| **Claude Desktop** (Windows) | `%APPDATA%\Claude\claude_desktop_config.json` |
| **Windsurf / Cline / прочее** | смотри MCP-доку клиента — тот же JSON |

#### Шаг 3 — первый запуск

При первом запуске сервер создаст пустой конфиг по пути `~/.config/mcp-sshpilot/servers.json` (`%USERPROFILE%\.config\mcp-sshpilot\servers.json` на Windows). Добавляй профили через тулзу `ssh_server_add` или редактируй JSON напрямую — за основу возьми [`servers.example.json`](./servers.example.json).

#### Обновление

```bash
npm i -g mcp-sshpilot@latest
```

> **Почему не `npx`?** MCP-клиенты запускают сервер при каждом старте сессии и применяют таймаут. `npx` проверяет реестр npm при каждом запуске (~3–5 с), что может превысить этот таймаут — сервер будет показываться как "не подключён", особенно в новых вкладках. Глобальная установка стартует мгновенно.

### Возможности

- 🔐 **Профили серверов** — AI работает по имени, не видит пароли/ключи
- 🌐 **Прокси** — SOCKS4 / SOCKS5 / HTTP / HTTPS CONNECT, глобально или per-server, с runtime override
- 🛡️ **Guard опасных команд** — `rm -rf`, `DROP TABLE`, `shutdown`, `chmod 777` и т.п. требуют явного подтверждения
- 📁 **SFTP** — read / write / list / stat / mkdir / rename / chmod / copy / delete
- 📦 **Bulk upload** — директории как tar.gz с распаковкой на сервере
- ⏳ **Background jobs** — для долгих/демонских команд
- ⚙️ **CRUD профилей агентом** — `ssh_server_add` / `update` / `remove`
- 📜 **Полный лог сессии** + ресурс `ssh://logs`
- 🔏 **Пиннинг ключа хоста** — первый коннект запоминает ключ сервера (TOFU); другой ключ отклоняется до отправки любых кредов
- 🌍 **Remote mode** — один HTTPS-сервер с зашифрованным хранилищем профилей для агентов на нескольких устройствах ([Remote mode](#remote-mode-1))

### Установка (альтернативы)

#### `npx` (без предустановки, медленный старт)

Если глобально ставить не хочется — `npx` работает как запасной вариант, но читай предупреждение в [Быстром старте](#быстрый-старт) про таймаут.

```json
{
  "mcpServers": {
    "sshpilot": {
      "command": "npx",
      "args": ["-y", "mcp-sshpilot"]
    }
  }
}
```

#### Из исходников (если хочешь править код)

```bash
git clone https://github.com/beekamai/mcp-sshpilot.git
cd mcp-sshpilot
npm install
npm run build
```

```json
{
  "mcpServers": {
    "sshpilot": {
      "command": "node",
      "args": ["C:/path/to/mcp-sshpilot/dist/index.js"]
    }
  }
}
```

Live-разработка без ребилда:

```json
{
  "mcpServers": {
    "sshpilot": {
      "command": "npx",
      "args": ["tsx", "C:/path/to/mcp-sshpilot/src/index.ts"]
    }
  }
}
```

### Конфиг серверов

Файл создаётся автоматически при первом запуске. Резолв пути (первый совпавший побеждает):

1. Env var `MCP_SSHPILOT_CONFIG` — явный путь (поддерживает `~/...`)
2. `<install_root>/servers.json` — только для **установки из исходников** (рядом с `dist/`). При `npx`/глобальной установке `<install_root>` лежит внутри кэша npm.
3. `~/.config/mcp-sshpilot/servers.json` — **дефолт для `npx` / `npm i -g`**. На Windows: `%USERPROFILE%\.config\mcp-sshpilot\servers.json`.

Управляй профилями через тулзы `ssh_server_add` / `update` / `remove`, или редактируй JSON напрямую:

```json
{
  "proxy": {
    "type": "socks5",
    "host": "127.0.0.1",
    "port": 1080
  },
  "servers": [
    {
      "name": "production",
      "host": "10.0.0.1",
      "port": 22,
      "username": "root",
      "password": "secret",
      "description": "идёт через глобальный socks5"
    },
    {
      "name": "staging",
      "host": "staging.example.com",
      "username": "deploy",
      "privateKeyPath": "~/.ssh/id_rsa",
      "passphrase": "...",
      "proxy": null,
      "description": "direct, перекрывает глобальный proxy"
    },
    {
      "name": "corp",
      "host": "10.1.2.3",
      "username": "ops",
      "privateKeyPath": "D:/keys/ops.pem",
      "proxy": {
        "type": "http",
        "host": "proxy.corp.local",
        "port": 8080,
        "username": "user",
        "password": "pass"
      }
    }
  ]
}
```

### Приоритет proxy

Порядок: **runtime override → `server.proxy` → `config.proxy`**.

| Что задано | Поведение |
|---|---|
| `ssh_proxy_disable` | direct, везде, до `ssh_proxy_enable` |
| `ssh_proxy_set` (runtime) | этот proxy для всех коннектов |
| `server.proxy: null` | direct для конкретного сервера, даже при глобальном |
| `server.proxy: {...}` | per-server proxy |
| `config.proxy: {...}` | дефолт для всех серверов без своего |

AI **не видит пароли проксей** при `ssh_proxy_status` — только `type://user@host:port`.

### Доступные инструменты

**Несколько подключений сразу.** Одна сессия держит до 16 подключений (в remote mode — 4 на сессию), названных
по профилю (без учёта регистра) или `user@host:port` для `ssh_connect`, так что параллельные субагенты одного клиента
не блокируют и не перенаправляют друг друга. Каждый инструмент, работающий с сервером, принимает необязательный
`profile`: если он задан — используется это подключение, а сохранённый, но ещё не подключённый профиль сначала
подключается (с теми же проверками пина, что у `ssh_connect_profile`); если не задан — используется единственное
открытое подключение. Когда открыто несколько, а `profile` не передан, вызов отклоняется и ничего не выполняется.
Подтверждения, фоновые задачи и temp-файлы привязаны к подключению, где появились: `ssh_execute_dangerous` /
`ssh_delete_confirm` всегда выполняются там же, `ssh_temp_upload` без `profile` заливает туда же.

#### Подключение / профили

| Tool | Описание |
|---|---|
| `ssh_connect` | Прямой коннект с явными параметрами (+ опциональный `proxy`); подключение называется `user@host:port` |
| `ssh_connect_profile` | Коннект по имени профиля. AI не видит креды. Необязателен: инструмент с `profile` подключит профиль сам |
| `ssh_list_profiles` | Список профилей с описанием и активным proxy |
| `ssh_status` | Статус всех открытых подключений, включая proxy и ключ хоста (`profile` — одно) |
| `ssh_disconnect` | `profile` закрывает одно, `all: true` — все; без них — только если открыто ровно одно. `cleanup_temp` удаляет его temp-файлы |
| `ssh_pin_host_keys` | Запинить ключи хостов без кредов: только обмен ключами, обрыв до аутентификации. По умолчанию — все профили без пина; существующий пин не перезаписывает (только stdio) |

#### CRUD серверов

| Tool | Описание |
|---|---|
| `ssh_server_add` | Добавить профиль в `servers.json` |
| `ssh_server_update` | Обновить поля (с `rename_to`). `proxy:null` — direct, `proxy:false` — снести поле. `reset_host_key:true` — сбросить запиненный ключ хоста (только stdio; в remote — `vault pin-host-key`) |
| `ssh_server_remove` | Удалить профиль по имени |

#### Управление proxy

| Tool | Описание |
|---|---|
| `ssh_proxy_status` | Глобальный + override + текущий применённый |
| `ssh_proxy_set` | Задать proxy. `scope: runtime` (default) или `global` (запись в `servers.json`) |
| `ssh_proxy_disable` | Отключить proxy. `scope: runtime` (default) или `global` (удалить из конфига) |
| `ssh_proxy_enable` | Снять runtime override, вернуться к конфигу |

#### Выполнение команд

| Tool | Описание |
|---|---|
| `ssh_execute` | Выполнить команду. Ненулевой выход дописывается в конец вывода как `[exit code: N]`. Жёсткий таймаут `timeout_ms` (default 300000). Для долгих/демонских команд используй `ssh_execute_background`, или отвязывай дескрипторы: `cmd > /dev/null 2>&1 < /dev/null & disown` |
| `ssh_execute_dangerous` | Подтвердить/отменить опасную по `confirmation_id` |
| `ssh_execute_background` | Запустить в фоне, возвращает `job_id` |
| `ssh_read_background` | Прочитать stdout/stderr/статус |
| `ssh_kill_background` | Убить фоновую задачу (SIGKILL, close channel) |
| `ssh_list_background` | Список всех job-ов с их подключением (`profile` — фильтр) |
| `ssh_pending_confirmations` | Список ожидающих подтверждения |

#### Файлы / SFTP

| Tool | Описание |
|---|---|
| `ssh_read_file` / `ssh_write_file` | Текстовые файлы напрямую |
| `ssh_list_dir` | `ls` директории |
| `ssh_file_info` | stat (размер, права, owner, mtime) |
| `ssh_mkdir` (recursive) / `ssh_rename` / `ssh_chmod` / `ssh_copy` | Стандартные операции |
| `ssh_delete` + `ssh_delete_confirm` | Удаление с подтверждением |
| `ssh_download_file` | Скачать в temp store, вернуть preview + ID; `as_base64: true` отдаёт весь файл inline в base64 до 2 MiB |
| `ssh_temp_list` / `read` / `write` / `upload` / `delete` / `cleanup` / `path` | Работа с temp store |
| `ssh_upload` | Файл → SFTP. Директория → tar.gz + upload + распаковка (`exclude` для паттернов) |

#### Логи

| Tool | Описание |
|---|---|
| `ssh_get_logs` | Лог всех подключений, записи помечены `[имя]`. `limit` — последние N, `profile` — одно подключение |

Также есть MCP-ресурс `ssh://logs`.

### Remote mode

Один сервер на твоей машине, и несколько агентов на разных устройствах работают с одними и теми же профилями по HTTPS:

```bash
export MCP_SSHPILOT_VAULT=./vault.json
mcp-sshpilot vault init --import ~/.config/mcp-sshpilot/servers.json --out recovery.token   # хранить офлайн
mcp-sshpilot vault add-device laptop --out laptop.token   # ключ разблокировки из $MCP_SSHPILOT_UNLOCK_KEY или stdin
mcp-sshpilot serve                                        # 127.0.0.1:8722, TLS спереди (в deploy/ — Docker + Caddy)

claude mcp add --transport http --scope user sshpilot https://mcp.example.com/mcp \
  --header "Authorization: Bearer <токен устройства>"
```

- Профили лежат в хранилище AES-256-GCM; сервер не хранит ключа, который его открывает. Токен устройства открывает его только на время сессии этого устройства.
- Свой токен на каждое устройство, отзывается сразу (`vault revoke-device`); сессии изолированы по устройствам.
- Plain HTTP не на loopback запрещён без явного флага; браузерные origin по умолчанию заблокированы; неудачная авторизация ограничена по частоте.
- Тулы, трогающие файловую систему самого сервера (`ssh_upload`, `ssh_temp_path`), и сырой `ssh_connect` в remote-режиме отключены.
- Ключи хостов перепиниваются только владельцем (`vault pin-host-key`), не моделью; `vault rotate` заодно меняет recovery key.

**Коннекторы Claude (веб/мобайл):** с `serve --oauth --public-url https://mcp.example.com` сервер ещё и говорит
по MCP OAuth. При добавлении его как custom connector страница согласия на твоём же сервере спрашивает device-токен
и даёт отметить, какие именно профили доступны этому коннектору; он получает собственную зашифрованную копию только
этих профилей, менять их не может, а отзывается через `vault revoke-grant` (или вместе с устройством, которое его
одобрило, `vault revoke-device`). Одобряй только подключение, которое сам только что начал.

Установка, модель угроз, пределы отзыва и деплой в Docker: **[docs/remote.md](./docs/remote.md)** (на английском).

### Безопасность и работа с секретами

- `servers.json` в `.gitignore` — **не коммить пароли**.
- Опасные команды (см. список ниже) автоматически блокируются и требуют `ssh_execute_dangerous` с `confirm: true`. `ssh_delete` тоже требует подтверждения. Та же проверка действует для `ssh_execute_background`. Подтверждение привязано к подключению, в котором выдано, и живёт 10 минут — после переключения сервера или переподключения оно отклоняется.
- AI видит только имя профиля, host:port, описание и `type://user@host:port` — никаких паролей и ключей.

#### Запретить агенту читать `servers.json`

В MCP-протоколе нет ACL на файлы — сам `mcp-sshpilot` никогда не возвращает содержимое `servers.json` модели, но *generic* файловые тулы агента (Read/Grep/Glob у Claude Code, file-search у Cursor и т.д.) могут открыть его сами. Пропиши явное правило:

```md
## Secrets policy

- NEVER read, open, grep, glob, cat, copy, attach, or otherwise access `servers.json`
  in this repository. It contains plaintext SSH credentials for `mcp-sshpilot`.
- If you need server info, call the `ssh_list_profiles` MCP tool — it returns a
  redacted view (name, host:port, description, proxy summary) without secrets.
- Treat `servers.json` as if it does not exist on the filesystem.
```

| Агент | Куда класть правило |
|---|---|
| **Claude Code** | `CLAUDE.md` в корне. Опционально — `Read(./servers.json)` в `permissions.deny` в `.claude/settings.json` |
| **OpenAI Codex CLI / ChatGPT Codex** | `AGENTS.md` в корне |
| **Cursor** | `.cursor/rules/secrets.mdc` (Project Rules), `alwaysApply: true` |
| **Windsurf** | `.windsurfrules` в корне |
| **GitHub Copilot Chat / Workspace** | `.github/copilot-instructions.md` |
| **Cline / Roo Code** | `.clinerules` в корне |

Belt-and-suspenders: храни `servers.json` вне workspace (вариант 3 в [Конфиг серверов](#конфиг-серверов)) — тогда никакой агент-тул его не достанет, независимо от правил.

#### Опасные паттерны

Удаление (`rm -rf`, `rmdir`), форматирование (`mkfs`, `dd if=`, `fdisk`, `parted`), система (`shutdown`, `reboot`, `init 0/6`), сервисы (`systemctl stop/disable/mask`, `service stop`), права (`chmod`, открывающий запись всем: `777`, `666`, `o+w`; `chown -R`, `userdel`, `groupdel`), сеть (`iptables -F`, `ufw disable`), пакеты (`apt remove/purge/autoremove`, `yum/dnf remove/erase`), БД (`DROP DATABASE/TABLE/USER`, `TRUNCATE`, `DELETE FROM`), Docker (`docker rm/rmi`, `system prune`, `docker compose` / `docker-compose` `down/rm`, `docker volume/network/image/container rm/prune`), процессы (`kill -9`, `killall`, `pkill`), пайпы в shell.

<details>
<summary>Структура проекта</summary>

```
src/
  index.ts       — entrypoint: разбор CLI, stdio-сервер
  cli.ts         — команды `vault ...` и `serve`
  mcp-server.ts  — MCP Server на каждый session ctx (тулы, ssh://logs)
  http.ts        — remote mode: Streamable HTTP, авторизация, сессии, лимиты, аудит
  oauth.ts       — OAuth для коннекторов Claude: discovery, регистрация, согласие, токены
  consent.ts     — HTML страниц согласия
  vault.ts       — зашифрованное хранилище профилей, токены устройств, гранты коннекторов
  types.ts       — общие типы
  state.ts       — состояние сессии (SessionCtx) и его очистка
  utils.ts       — id, форматирование байт/прав/логов
  danger.ts      — паттерны и checkDangerousCommand
  config.ts      — ProfileStore, хранилище servers.json, profileToConnectConfig
  proxy.ts       — validate/describe/resolve + buildProxySocket + HTTP CONNECT
  ssh-core.ts    — connect/disconnect/execute, пиннинг ключа хоста, background jobs
  ssh-fs.ts      — SFTP операции + bulk upload (tar.gz)
  temp.ts        — temp file store (квота на сессию в remote mode)
  tools.ts       — MCP tool definitions, фильтр для remote mode
  handlers.ts    — диспатч tool calls
test/            — тесты node:test (npm test)
deploy/          — Dockerfile, docker-compose.yml, Caddyfile
docs/remote.md   — гайд по remote mode и модель угроз
```

</details>

### Лицензия

MIT
