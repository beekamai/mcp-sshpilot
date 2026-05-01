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

#### Connection / profiles

| Tool | Description |
|---|---|
| `ssh_connect` | Direct connect with explicit params (+ optional `proxy`) |
| `ssh_connect_profile` | Connect by profile name. AI does not see credentials |
| `ssh_list_profiles` | Profile list with description and active proxy |
| `ssh_status` | Session status (incl. proxy used) |
| `ssh_disconnect` | Disconnect (`cleanup_temp` clears temp store) |

#### Server CRUD

| Tool | Description |
|---|---|
| `ssh_server_add` | Add a profile to `servers.json` |
| `ssh_server_update` | Update fields (with `rename_to`). `proxy:null` forces direct, `proxy:false` removes the field |
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
| `ssh_execute` | Run a command. Hard timeout `timeout_ms` (default 300000). For long-running / daemon-like commands use `ssh_execute_background` instead, or detach descriptors: `cmd > /dev/null 2>&1 < /dev/null & disown` |
| `ssh_execute_dangerous` | Confirm/cancel via `confirmation_id` |
| `ssh_execute_background` | Run in background, returns `job_id` |
| `ssh_read_background` | Read stdout/stderr/status |
| `ssh_kill_background` | Kill a background job (SIGKILL, close channel) |
| `ssh_list_background` | List all jobs |
| `ssh_pending_confirmations` | List awaiting confirmations |

#### Files / SFTP

| Tool | Description |
|---|---|
| `ssh_read_file` / `ssh_write_file` | Text files directly |
| `ssh_list_dir` | `ls` of a directory |
| `ssh_file_info` | stat (size, mode, owner, mtime) |
| `ssh_mkdir` (recursive) / `ssh_rename` / `ssh_chmod` / `ssh_copy` | Standard ops |
| `ssh_delete` + `ssh_delete_confirm` | Delete with confirmation |
| `ssh_download_file` | Download to temp store, return preview + ID |
| `ssh_temp_list` / `read` / `write` / `upload` / `delete` / `cleanup` / `path` | Temp store (edit before re-upload) |
| `ssh_upload` | File → SFTP. Directory → tar.gz + upload + extract (`exclude` patterns supported) |

#### Logs

| Tool | Description |
|---|---|
| `ssh_get_logs` | Current session log. `limit` — last N |

The MCP resource `ssh://logs` is also exposed.

### Security & secret hygiene

- `servers.json` is in `.gitignore` — **don't commit credentials**.
- Dangerous commands (full list below) are auto-blocked and require `ssh_execute_dangerous` with `confirm: true`. `ssh_delete` also requires confirmation.
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

Removal (`rm -rf`, `rmdir`), formatting (`mkfs`, `dd if=`, `fdisk`, `parted`), system (`shutdown`, `reboot`, `init 0/6`), services (`systemctl stop/disable/mask`, `service stop`), permissions (`chmod *7*`, `chown -R`, `userdel`, `groupdel`), network (`iptables -F`, `ufw disable`), packages (`apt remove/purge/autoremove`, `yum/dnf remove/erase`), DB (`DROP DATABASE/TABLE/USER`, `TRUNCATE`, `DELETE FROM`), Docker (`docker rm/rmi`, `system prune`, `docker-compose down`), processes (`kill -9`, `killall`, `pkill`), pipes into shell.

<details>
<summary>Project layout</summary>

```
src/
  index.ts       — entrypoint (Server, transport, ssh://logs resource)
  types.ts       — shared types
  state.ts       — global state (session, pending, jobs, override)
  utils.ts       — id, byte/perm/log formatters
  danger.ts      — patterns + checkDangerousCommand
  config.ts      — servers.json: load/save/CRUD/profileToConnectConfig
  proxy.ts       — validate/describe/resolve + buildProxySocket + HTTP CONNECT
  ssh-core.ts    — connect/disconnect/execute + background jobs
  ssh-fs.ts      — SFTP ops + bulk upload (tar.gz)
  temp.ts        — temp file store
  tools.ts       — MCP tool definitions
  handlers.ts    — tool call dispatcher
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

#### Подключение / профили

| Tool | Описание |
|---|---|
| `ssh_connect` | Прямой коннект с явными параметрами (+ опциональный `proxy`) |
| `ssh_connect_profile` | Коннект по имени профиля. AI не видит креды |
| `ssh_list_profiles` | Список профилей с описанием и активным proxy |
| `ssh_status` | Статус сессии (включая использованный proxy) |
| `ssh_disconnect` | Отключиться (`cleanup_temp` чистит temp store) |

#### CRUD серверов

| Tool | Описание |
|---|---|
| `ssh_server_add` | Добавить профиль в `servers.json` |
| `ssh_server_update` | Обновить поля (с `rename_to`). `proxy:null` — direct, `proxy:false` — снести поле |
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
| `ssh_execute` | Выполнить команду. Жёсткий таймаут `timeout_ms` (default 300000). Для долгих/демонских команд используй `ssh_execute_background`, или отвязывай дескрипторы: `cmd > /dev/null 2>&1 < /dev/null & disown` |
| `ssh_execute_dangerous` | Подтвердить/отменить опасную по `confirmation_id` |
| `ssh_execute_background` | Запустить в фоне, возвращает `job_id` |
| `ssh_read_background` | Прочитать stdout/stderr/статус |
| `ssh_kill_background` | Убить фоновую задачу (SIGKILL, close channel) |
| `ssh_list_background` | Список всех job-ов |
| `ssh_pending_confirmations` | Список ожидающих подтверждения |

#### Файлы / SFTP

| Tool | Описание |
|---|---|
| `ssh_read_file` / `ssh_write_file` | Текстовые файлы напрямую |
| `ssh_list_dir` | `ls` директории |
| `ssh_file_info` | stat (размер, права, owner, mtime) |
| `ssh_mkdir` (recursive) / `ssh_rename` / `ssh_chmod` / `ssh_copy` | Стандартные операции |
| `ssh_delete` + `ssh_delete_confirm` | Удаление с подтверждением |
| `ssh_download_file` | Скачать в temp store, вернуть preview + ID |
| `ssh_temp_list` / `read` / `write` / `upload` / `delete` / `cleanup` / `path` | Работа с temp store |
| `ssh_upload` | Файл → SFTP. Директория → tar.gz + upload + распаковка (`exclude` для паттернов) |

#### Логи

| Tool | Описание |
|---|---|
| `ssh_get_logs` | Лог текущей сессии. `limit` — последние N |

Также есть MCP-ресурс `ssh://logs`.

### Безопасность и работа с секретами

- `servers.json` в `.gitignore` — **не коммить пароли**.
- Опасные команды (см. список ниже) автоматически блокируются и требуют `ssh_execute_dangerous` с `confirm: true`. `ssh_delete` тоже требует подтверждения.
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

Удаление (`rm -rf`, `rmdir`), форматирование (`mkfs`, `dd if=`, `fdisk`, `parted`), система (`shutdown`, `reboot`, `init 0/6`), сервисы (`systemctl stop/disable/mask`, `service stop`), права (`chmod *7*`, `chown -R`, `userdel`, `groupdel`), сеть (`iptables -F`, `ufw disable`), пакеты (`apt remove/purge/autoremove`, `yum/dnf remove/erase`), БД (`DROP DATABASE/TABLE/USER`, `TRUNCATE`, `DELETE FROM`), Docker (`docker rm/rmi`, `system prune`, `docker-compose down`), процессы (`kill -9`, `killall`, `pkill`), пайпы в shell.

<details>
<summary>Структура проекта</summary>

```
src/
  index.ts       — entrypoint (Server, transport, ресурс ssh://logs)
  types.ts       — общие типы
  state.ts       — глобальное состояние (сессия, pending, jobs, override)
  utils.ts       — id, форматирование байт/прав/логов
  danger.ts      — паттерны и checkDangerousCommand
  config.ts      — servers.json: load/save/CRUD/profileToConnectConfig
  proxy.ts       — validate/describe/resolve + buildProxySocket + HTTP CONNECT
  ssh-core.ts    — connect/disconnect/execute + background jobs
  ssh-fs.ts      — SFTP операции + bulk upload (tar.gz)
  temp.ts        — temp file store
  tools.ts       — MCP tool definitions
  handlers.ts    — диспатч tool calls
```

</details>

### Лицензия

MIT
