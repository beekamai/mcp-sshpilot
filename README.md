# mcp-sshpilot

[![npm version](https://img.shields.io/npm/v/mcp-sshpilot.svg)](https://www.npmjs.com/package/mcp-sshpilot)
[![npm downloads](https://img.shields.io/npm/dm/mcp-sshpilot.svg)](https://www.npmjs.com/package/mcp-sshpilot)
[![node](https://img.shields.io/node/v/mcp-sshpilot.svg)](https://nodejs.org)
[![license](https://img.shields.io/npm/l/mcp-sshpilot.svg)](./LICENSE)

> 🇬🇧 [English](#english) · 🇷🇺 [Русский](#русский)

---

## English

MCP server that lets an AI agent work on your servers over SSH: commands, files, background jobs, proxies. The agent
uses saved profiles by name and never sees passwords or keys.

### Quick start

```bash
npm i -g mcp-sshpilot
claude mcp add sshpilot --scope user mcp-sshpilot
```

Check with `claude mcp list` → `sshpilot ... ✓ Connected`. On first start the server creates an empty
`~/.config/mcp-sshpilot/servers.json`; add servers with the `ssh_server_add` tool or edit the file
([`servers.example.json`](./servers.example.json)).

Other MCP clients use the same JSON:

```json
{ "mcpServers": { "sshpilot": { "command": "mcp-sshpilot" } } }
```

| Client | Config file |
|---|---|
| Cursor | `~/.cursor/mcp.json` or `<project>/.cursor/mcp.json` |
| Claude Desktop | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`, Windows `%APPDATA%\Claude\claude_desktop_config.json` |
| Windsurf, Cline, others | the client's MCP config, same format |

<details>
<summary>Windows: if the server does not start</summary>

Some clients start MCP servers without a shell, and on Windows `mcp-sshpilot` is a `.cmd` shim they cannot run
(`spawn ENOENT`). Point them at Node directly; `npm root -g` prints the folder:

```json
{ "mcpServers": { "sshpilot": { "command": "node", "args": ["C:/Users/<you>/AppData/Roaming/npm/node_modules/mcp-sshpilot/dist/index.js"] } } }
```

Avoid `npx -y mcp-sshpilot`: it checks the registry on every start and can miss the client's startup timeout.

</details>

Update: `npm i -g mcp-sshpilot@latest`, then restart the client.

### Features

- 🔐 **Profiles** — the agent connects by name; credentials stay in the config and never reach it
- 🔀 **Several servers at once** — one session holds up to 16 connections, so parallel agents don't block or retarget each other
- 🔏 **Host-key pinning** — the first connection pins the key, any other key is refused before credentials are sent
- 🛡️ **Dangerous-command guard** — `rm -rf`, `DROP TABLE`, `shutdown`, … need an explicit confirmation
- 📁 **SFTP** — read, write, list, copy, chmod, delete; folders upload as tar.gz
- ⏳ **Background jobs** for long-running commands
- 🌐 **Proxies** — SOCKS4/5, HTTP/HTTPS CONNECT, global or per server
- 🌍 **Remote mode** — one HTTPS server with an encrypted vault for agents on several devices and Claude connectors

### Profiles

`servers.json` is found in this order: `$MCP_SSHPILOT_CONFIG` → `servers.json` next to `dist/` (source checkout) →
`~/.config/mcp-sshpilot/servers.json`.

```json
{
  "proxy": { "type": "socks5", "host": "127.0.0.1", "port": 1080 },
  "servers": [
    { "name": "prod", "host": "10.0.0.1", "username": "root", "password": "secret" },
    {
      "name": "staging",
      "host": "staging.example.com",
      "username": "deploy",
      "privateKeyPath": "~/.ssh/id_ed25519",
      "proxy": null,
      "description": "direct, ignores the global proxy"
    }
  ]
}
```

Proxy order: runtime override (`ssh_proxy_set` / `ssh_proxy_disable`) → the profile's `proxy` (`null` = direct) →
the global `proxy`. After the first connection a profile also carries `hostKeySha256`, its pinned host key.

### Several servers at once

Every tool that acts on a server takes an optional `profile`. With one open connection you can leave it out, as
before. With several, name the server: `ssh_execute { "profile": "prod", "command": "uptime" }`. A profile that is
not connected yet is connected on first use. If several connections are open and `profile` is missing, the call is
refused and nothing runs. Confirmations, background jobs and temp files stay bound to the server they came from.

### Tools

| Group | Tools |
|---|---|
| Connections | `ssh_connect_profile`, `ssh_connect` (explicit host/user/key), `ssh_status`, `ssh_disconnect` (`profile` or `all`), `ssh_pin_host_keys` (pin keys without logging in) |
| Profiles | `ssh_list_profiles`, `ssh_server_add`, `ssh_server_update` (`rename_to`, `reset_host_key`), `ssh_server_remove` |
| Proxy | `ssh_proxy_status`, `ssh_proxy_set`, `ssh_proxy_disable`, `ssh_proxy_enable` (`scope`: `runtime` or `global`) |
| Commands | `ssh_execute` (`timeout_ms`, exit code reported), `ssh_execute_dangerous` (confirm), `ssh_pending_confirmations` |
| Background | `ssh_execute_background`, `ssh_read_background`, `ssh_kill_background`, `ssh_list_background` |
| Files | `ssh_read_file`, `ssh_write_file`, `ssh_list_dir`, `ssh_file_info`, `ssh_mkdir`, `ssh_rename`, `ssh_copy`, `ssh_chmod`, `ssh_delete` + `ssh_delete_confirm`, `ssh_upload` (file or folder) |
| Temp store | `ssh_download_file` (`as_base64` inline up to 2 MiB), `ssh_temp_list`, `ssh_temp_read`, `ssh_temp_write`, `ssh_temp_upload`, `ssh_temp_delete`, `ssh_temp_cleanup`, `ssh_temp_path` |
| Logs | `ssh_get_logs`, resource `ssh://logs` |

### Remote mode

One server on a box you control; every device gets its own revocable token, profiles live in an AES-256-GCM vault
the server cannot open by itself, and Claude connectors (web, mobile) get OAuth grants limited to the profiles you
tick.

```bash
mcp-sshpilot vault init --import ~/.config/mcp-sshpilot/servers.json --out recovery.token   # keep offline
mcp-sshpilot vault add-device laptop --out laptop.token
mcp-sshpilot serve --trust-proxy            # 127.0.0.1:8722 behind nginx/Caddy with TLS
claude mcp add --transport http --scope user sshpilot https://mcp.example.com/mcp --header "Authorization: Bearer <token>"
```

Remote mode has no raw `ssh_connect` and no access to the server's own disk, and refuses profiles without a pinned
host key unless started with `--allow-tofu`. Setup (systemd + nginx), connectors, threat model and limits:
**[docs/remote.md](./docs/remote.md)**.

### Security

- Keep `servers.json` out of git (it holds plaintext credentials) and preferably outside any workspace.
- Tool output shows name, `user@host:port`, description and `type://user@host:port` for proxies — never secrets.
  `ssh_upload` refuses the config and key files themselves.
- Dangerous commands and deletes wait for confirmation (10 minutes, only on the connection they were issued on).

The agent's own file tools can still open `servers.json`. Add a rule to `CLAUDE.md`, `AGENTS.md`,
`.cursor/rules/*.mdc`, `.windsurfrules`, `.clinerules` or `.github/copilot-instructions.md`:

```md
- NEVER read, open, grep, copy or attach `servers.json` (mcp-sshpilot credentials).
  Use the `ssh_list_profiles` tool to see servers.
```

<details>
<summary>Commands that need confirmation</summary>

Removal (`rm -rf`, `rmdir`), disks (`mkfs`, `dd if=`, `fdisk`, `parted`), power (`shutdown`, `reboot`, `init 0/6`),
services (`systemctl stop/disable/mask`, `service stop`), permissions (world-writable `chmod`, `chown -R`,
`userdel`, `groupdel`), firewall (`iptables -F`, `ufw disable`), packages (`apt remove/purge/autoremove`,
`yum/dnf remove/erase`), databases (`DROP DATABASE/TABLE/USER`, `TRUNCATE`, `DELETE FROM`), Docker (`docker rm/rmi`,
`system prune`, `compose down/rm`, `volume/network/image/container rm/prune`), processes (`kill -9`, `killall`,
`pkill`), piping into a shell.

</details>

### Development

```bash
git clone https://github.com/beekamai/mcp-sshpilot.git && cd mcp-sshpilot
npm ci
npm test        # tsc + node:test
```

Run from source with `"command": "node", "args": ["<repo>/dist/index.js"]`.

<details>
<summary>Project layout</summary>

```
src/
  index.ts       entry point: CLI or stdio server
  cli.ts         `vault ...` and `serve` commands
  mcp-server.ts  one MCP server per session (tools, ssh://logs)
  http.ts        remote mode: Streamable HTTP, auth, sessions, limits, audit
  oauth.ts       OAuth for Claude connectors
  consent.ts     consent page HTML
  vault.ts       encrypted profile vault, device tokens, connector grants
  state.ts       per-session state and its connections
  ssh-core.ts    connect, reconnect, host-key pinning, commands, background jobs
  ssh-fs.ts      SFTP operations and folder upload
  handlers.ts    tool dispatcher
  tools.ts       tool definitions per mode
  config.ts      servers.json store
  proxy.ts       proxy resolution and HTTP CONNECT
  temp.ts        temp file store
  danger.ts      dangerous-command patterns
  types.ts, utils.ts
test/            node:test suites
docs/remote.md   remote mode guide and threat model
```

</details>

### License

MIT

---

## Русский

MCP-сервер, через который ИИ-агент работает с вашими серверами по SSH: команды, файлы, фоновые задачи, прокси.
Агент подключается к сохранённым профилям по имени и не видит ни паролей, ни ключей.

### Быстрый старт

```bash
npm i -g mcp-sshpilot
claude mcp add sshpilot --scope user mcp-sshpilot
```

Проверка: `claude mcp list` → `sshpilot ... ✓ Connected`. При первом запуске сервер создаёт пустой
`~/.config/mcp-sshpilot/servers.json`; серверы добавляются инструментом `ssh_server_add` или правкой файла
([`servers.example.json`](./servers.example.json)).

Другие MCP-клиенты используют тот же JSON:

```json
{ "mcpServers": { "sshpilot": { "command": "mcp-sshpilot" } } }
```

| Клиент | Файл конфига |
|---|---|
| Cursor | `~/.cursor/mcp.json` или `<проект>/.cursor/mcp.json` |
| Claude Desktop | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`, Windows `%APPDATA%\Claude\claude_desktop_config.json` |
| Windsurf, Cline и другие | MCP-конфиг клиента, тот же формат |

<details>
<summary>Windows: если сервер не стартует</summary>

Часть клиентов запускает MCP-серверы без шелла, а на Windows `mcp-sshpilot` — это `.cmd`-обёртка, которую они
запустить не могут (`spawn ENOENT`). Укажите Node напрямую; папку покажет `npm root -g`:

```json
{ "mcpServers": { "sshpilot": { "command": "node", "args": ["C:/Users/<you>/AppData/Roaming/npm/node_modules/mcp-sshpilot/dist/index.js"] } } }
```

`npx -y mcp-sshpilot` лучше не использовать: он ходит в реестр при каждом старте и может не уложиться в таймаут
клиента.

</details>

Обновление: `npm i -g mcp-sshpilot@latest`, затем перезапуск клиента.

### Возможности

- 🔐 **Профили** — агент подключается по имени, креды остаются в конфиге и до него не доходят
- 🔀 **Несколько серверов сразу** — до 16 подключений в одной сессии, параллельные агенты не ждут и не перебивают друг друга
- 🔏 **Закрепление ключа хоста** — первое подключение запоминает ключ, любой другой отвергается до отправки кредов
- 🛡️ **Защита от опасных команд** — `rm -rf`, `DROP TABLE`, `shutdown`, … требуют явного подтверждения
- 📁 **SFTP** — чтение, запись, листинг, копирование, chmod, удаление; папки заливаются tar.gz
- ⏳ **Фоновые задачи** для долгих команд
- 🌐 **Прокси** — SOCKS4/5, HTTP/HTTPS CONNECT, общий или на сервер
- 🌍 **Remote mode** — один HTTPS-сервер с зашифрованным хранилищем для агентов на разных устройствах и коннекторов Claude

### Профили

`servers.json` ищется в таком порядке: `$MCP_SSHPILOT_CONFIG` → `servers.json` рядом с `dist/` (запуск из
исходников) → `~/.config/mcp-sshpilot/servers.json`.

```json
{
  "proxy": { "type": "socks5", "host": "127.0.0.1", "port": 1080 },
  "servers": [
    { "name": "prod", "host": "10.0.0.1", "username": "root", "password": "secret" },
    {
      "name": "staging",
      "host": "staging.example.com",
      "username": "deploy",
      "privateKeyPath": "~/.ssh/id_ed25519",
      "proxy": null,
      "description": "напрямую, без общего прокси"
    }
  ]
}
```

Порядок прокси: runtime-переопределение (`ssh_proxy_set` / `ssh_proxy_disable`) → `proxy` профиля (`null` —
напрямую) → общий `proxy`. После первого подключения в профиле появляется `hostKeySha256` — закреплённый ключ хоста.

### Несколько серверов сразу

Каждый инструмент, который работает с сервером, принимает необязательный `profile`. Если подключение одно, его
можно не указывать, как раньше. Если несколько — назовите сервер: `ssh_execute { "profile": "prod", "command":
"uptime" }`. Ещё не подключённый профиль подключится при первом вызове. Если открыто несколько подключений, а
`profile` не указан, вызов отклоняется и ничего не выполняется. Подтверждения, фоновые задачи и temp-файлы
остаются привязаны к серверу, откуда пришли.

### Инструменты

| Группа | Инструменты |
|---|---|
| Подключения | `ssh_connect_profile`, `ssh_connect` (явные host/user/ключ), `ssh_status`, `ssh_disconnect` (`profile` или `all`), `ssh_pin_host_keys` (закрепить ключи без входа) |
| Профили | `ssh_list_profiles`, `ssh_server_add`, `ssh_server_update` (`rename_to`, `reset_host_key`), `ssh_server_remove` |
| Прокси | `ssh_proxy_status`, `ssh_proxy_set`, `ssh_proxy_disable`, `ssh_proxy_enable` (`scope`: `runtime` или `global`) |
| Команды | `ssh_execute` (`timeout_ms`, код выхода в выводе), `ssh_execute_dangerous` (подтверждение), `ssh_pending_confirmations` |
| Фоновые | `ssh_execute_background`, `ssh_read_background`, `ssh_kill_background`, `ssh_list_background` |
| Файлы | `ssh_read_file`, `ssh_write_file`, `ssh_list_dir`, `ssh_file_info`, `ssh_mkdir`, `ssh_rename`, `ssh_copy`, `ssh_chmod`, `ssh_delete` + `ssh_delete_confirm`, `ssh_upload` (файл или папка) |
| Temp-хранилище | `ssh_download_file` (`as_base64` целиком до 2 МиБ), `ssh_temp_list`, `ssh_temp_read`, `ssh_temp_write`, `ssh_temp_upload`, `ssh_temp_delete`, `ssh_temp_cleanup`, `ssh_temp_path` |
| Логи | `ssh_get_logs`, ресурс `ssh://logs` |

### Remote mode

Один сервер на вашей машине: у каждого устройства свой отзываемый токен, профили лежат в хранилище AES-256-GCM,
которое сервер сам открыть не может, а коннекторы Claude (веб, мобильный) получают OAuth-доступ только к
отмеченным профилям.

```bash
mcp-sshpilot vault init --import ~/.config/mcp-sshpilot/servers.json --out recovery.token   # хранить офлайн
mcp-sshpilot vault add-device laptop --out laptop.token
mcp-sshpilot serve --trust-proxy            # 127.0.0.1:8722 за nginx/Caddy с TLS
claude mcp add --transport http --scope user sshpilot https://mcp.example.com/mcp --header "Authorization: Bearer <token>"
```

В remote mode нет raw `ssh_connect` и доступа к диску самого сервера, а профили без закреплённого ключа хоста
отклоняются, если сервер не запущен с `--allow-tofu`. Установка (systemd + nginx), коннекторы, модель угроз и
лимиты: **[docs/remote.md](./docs/remote.md)**.

### Безопасность

- `servers.json` не коммитить (там креды открытым текстом) и лучше держать вне рабочих папок.
- В выводе инструментов — имя, `user@host:port`, описание и `type://user@host:port` для прокси, но не секреты.
  `ssh_upload` отказывается заливать сам конфиг и файлы ключей.
- Опасные команды и удаления ждут подтверждения (10 минут, только на том подключении, где выданы).

Собственные файловые инструменты агента всё равно могут открыть `servers.json`. Добавьте правило в `CLAUDE.md`,
`AGENTS.md`, `.cursor/rules/*.mdc`, `.windsurfrules`, `.clinerules` или `.github/copilot-instructions.md`:

```md
- NEVER read, open, grep, copy or attach `servers.json` (mcp-sshpilot credentials).
  Use the `ssh_list_profiles` tool to see servers.
```

<details>
<summary>Команды, требующие подтверждения</summary>

Удаление (`rm -rf`, `rmdir`), диски (`mkfs`, `dd if=`, `fdisk`, `parted`), питание (`shutdown`, `reboot`,
`init 0/6`), службы (`systemctl stop/disable/mask`, `service stop`), права (`chmod` с записью для всех,
`chown -R`, `userdel`, `groupdel`), файрвол (`iptables -F`, `ufw disable`), пакеты (`apt remove/purge/autoremove`,
`yum/dnf remove/erase`), базы (`DROP DATABASE/TABLE/USER`, `TRUNCATE`, `DELETE FROM`), Docker (`docker rm/rmi`,
`system prune`, `compose down/rm`, `volume/network/image/container rm/prune`), процессы (`kill -9`, `killall`,
`pkill`), передача вывода в шелл.

</details>

### Разработка

```bash
git clone https://github.com/beekamai/mcp-sshpilot.git && cd mcp-sshpilot
npm ci
npm test        # tsc + node:test
```

Запуск из исходников: `"command": "node", "args": ["<репозиторий>/dist/index.js"]`.

<details>
<summary>Структура проекта</summary>

```
src/
  index.ts       точка входа: CLI или stdio-сервер
  cli.ts         команды `vault ...` и `serve`
  mcp-server.ts  MCP-сервер на каждую сессию (инструменты, ssh://logs)
  http.ts        remote mode: Streamable HTTP, авторизация, сессии, лимиты, аудит
  oauth.ts       OAuth для коннекторов Claude
  consent.ts     HTML страницы согласия
  vault.ts       зашифрованное хранилище, токены устройств, гранты коннекторов
  state.ts       состояние сессии и её подключения
  ssh-core.ts    подключение, переподключение, закрепление ключей, команды, фоновые задачи
  ssh-fs.ts      операции SFTP и заливка папок
  handlers.ts    диспетчер инструментов
  tools.ts       описания инструментов по режимам
  config.ts      хранилище servers.json
  proxy.ts       выбор прокси и HTTP CONNECT
  temp.ts        temp-хранилище
  danger.ts      шаблоны опасных команд
  types.ts, utils.ts
test/            тесты node:test
docs/remote.md   руководство по remote mode и модель угроз
```

</details>

### Лицензия

MIT
