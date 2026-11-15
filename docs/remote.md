# Remote mode

By default mcp-sshpilot is a local stdio server: one MCP client, one process, profiles in a plaintext
`servers.json` on the same machine. **Remote mode** runs one server on a box you control, so several of your
agents on different devices (laptop, desktop, a CI runner) share the same saved SSH profiles over HTTPS.

```
 agent (device A) ─┐   HTTPS + Bearer token        ┌─ Caddy (TLS, Host check) ─ sshpilot serve ─── SSH ──> your servers
 agent (device B) ─┘ ─────────────────────────────>│                            (vault.json, encrypted)
```

- Transport: MCP Streamable HTTP, one endpoint `/mcp` (POST/GET/DELETE) and a bare `/healthz`.
- Auth: a per-device bearer token on **every** request.
- Profiles: an encrypted vault file. The server keeps no key that can decrypt it; a device token unlocks it for
  the lifetime of that device's session only.

Everything below is secure by default. Every relaxation needs an explicit flag.

---

## Quick start: Docker + Caddy

Requirements: a host with Docker, a DNS name pointing at it (`mcp.example.com` below), ports 80/443 open.

**1. Build the vault on a trusted machine** (where your `servers.json` and key files live). Import inlines every
`privateKeyPath` file into the encrypted vault:

```bash
export MCP_SSHPILOT_VAULT=./vault.json
npx mcp-sshpilot vault init --import ~/.config/mcp-sshpilot/servers.json --out ./recovery.token
# Store recovery.token offline (password manager), then delete the file.

# One device per agent/machine. The unlock key (recovery key or an existing device token) is read from
# MCP_SSHPILOT_UNLOCK_KEY or stdin, never from argv.
npx mcp-sshpilot vault add-device laptop  --out ./laptop.token
npx mcp-sshpilot vault add-device desktop --out ./desktop.token
npx mcp-sshpilot vault list-devices
```

`vault.json` is safe to copy: without a token or the recovery key it is ciphertext. Copy it to the server **once**,
for the first deployment. After that the server's copy is the live one (revocations, TOFU pins and profiles added
through the server land there): change it in place with the `vault` service below, never by copying an older vault
over it, which would silently undo all of that.

**2. Deploy**

```bash
git clone https://github.com/beekamai/mcp-sshpilot && cd mcp-sshpilot/deploy
echo "SSHPILOT_DOMAIN=mcp.example.com" > .env
mkdir -p data && cp /path/to/vault.json data/ && sudo chown -R 1000:1000 data && chmod 700 data
docker compose up -d --build
curl https://mcp.example.com/healthz        # -> ok
```

Only Caddy publishes ports. `sshpilot` listens on plain HTTP inside the compose network (that is what
`--insecure-http` in the compose file means) and trusts Caddy's `X-Forwarded-For` (`--trust-proxy`).
The container runs as a non-root user with a read-only root filesystem, `cap_drop: ALL` and
`no-new-privileges`; the per-session temp stores live in a size-limited tmpfs.

Vault commands can also run on the server, through the separate `vault` service (interactive, the unlock key
prompt does not echo):

```bash
docker compose run --rm vault add-device ci-runner
docker compose run --rm vault revoke-device laptop
docker compose run --rm vault pin-host-key prod SHA256:...
```

Use the `vault` service, never `docker compose run sshpilot vault ...` or a plain `docker run`: whatever a container
prints to stdout goes to Docker's log driver, which may keep it on the same disk as the vault (journald on
Fedora/RHEL packages, `json-file` everywhere else until the container is removed). The `vault` service has logging
turned off and no network. On your own machine, `--out <file>` (created 0600) keeps a secret off the terminal too.

The image's default command listens on the container's loopback only, so a bare `docker run -p 8722:8722` exposes
nothing; the plain-HTTP flags exist only in the compose file, where sshpilot is reachable from Caddy alone.

**3. Connect an agent.** Claude Code:

```bash
claude mcp add --transport http --scope user sshpilot https://mcp.example.com/mcp \
  --header "Authorization: Bearer sshp_xxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

Never put a literal token into a project-scoped `.mcp.json` that could be committed. If you need a project
config, reference an environment variable instead: `"headers": { "Authorization": "Bearer ${SSHPILOT_TOKEN}" }`.
Any MCP client that supports Streamable HTTP and custom headers works the same way.

## Without Docker

```bash
npm i -g mcp-sshpilot
MCP_SSHPILOT_VAULT=/srv/sshpilot/vault.json mcp-sshpilot serve                      # 127.0.0.1:8722, put a TLS proxy in front
MCP_SSHPILOT_VAULT=/srv/sshpilot/vault.json mcp-sshpilot serve --host 0.0.0.0 \
  --tls-cert /etc/ssl/sshpilot.crt --tls-key /etc/ssl/sshpilot.key                 # native TLS (1.2+)
```

| Flag | Meaning |
|---|---|
| `--host` / `--port` | Bind address, default `127.0.0.1:8722`. |
| `--tls-cert` / `--tls-key` | Serve HTTPS directly. Both or neither. |
| `--insecure-http` | Allow plain HTTP on a non-loopback address. Without it the server refuses to start. Only for a private network behind a TLS-terminating proxy. |
| `--trust-proxy` | Take the client IP from the right-most `X-Forwarded-For` entry, honoured only from a loopback or private-network peer and only when it is an IP address (otherwise the peer address counts). Only behind a proxy you control: without one, clients can spoof their IP and dodge the auth rate limit. Behind a local proxy, set it, or every client shares the proxy's address for that limit. The proxy must append the address it saw (Caddy does; nginx: `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` or `$remote_addr`). |
| `--allow-local-targets` | Let profiles and proxies point at this host's own loopback, link-local or cloud-metadata addresses (127.0.0.0/8, ::1, 169.254.0.0/16, fe80::/10, 0.0.0.0/8, 100.100.100.200, fd00:ec2::254). Refused by default. |
| `--allowed-origin <origin>` | Exact `scheme://host[:port]` a browser-based client may call from (repeatable). Default: none. Requests without `Origin` (CLI agents) are not affected. |
| `--oauth`, `--public-url`, `--oauth-redirect` | Claude connectors; see the next section. |

## Claude connectors (OAuth)

Claude on the web and on mobile (and Claude Desktop's custom connectors) cannot send a static `Authorization`
header: a custom connector speaks the MCP authorization spec (OAuth 2.1, authorization code with PKCE, dynamic
client registration). With `--oauth`, the server is its own authorization server for that. Connector requests do
**not** come from your phone: they come from Anthropic's cloud, which holds the tokens. So this path is deliberately
narrower than a device token: when you connect, you pick exactly which profiles the connector may use, and the
limit is cryptographic, not a check in the code.

**Enable it** (OAuth is off by default):

```bash
mcp-sshpilot serve --oauth --public-url https://mcp.example.com      # plus your usual flags
```

In the Docker deployment, append `"--oauth", "--public-url", "https://mcp.example.com"` to the `command:` of the
`sshpilot` service (the shipped Caddyfile already routes `/.well-known/oauth-*` and `/oauth/*`). Then in Claude:
Settings -> Connectors -> Add custom connector -> `https://mcp.example.com/mcp`.

| Flag | Meaning |
|---|---|
| `--oauth` | Serve the OAuth endpoints and accept connector access tokens on `/mcp`. Device tokens keep working as before. |
| `--public-url <origin>` | The external `https://host[:port]` clients reach (no path). Issuer of the tokens; the protected resource is `<origin>/mcp`. Required with `--oauth`; plain `http` only for localhost. |
| `--oauth-redirect <uri>` | Another redirect URI a client may register (exact match, repeatable). Default allowlist: `https://claude.ai/api/mcp/auth_callback`, `https://claude.com/api/mcp/auth_callback`. |

Endpoints: `/.well-known/oauth-protected-resource` (and `.../mcp`), `/.well-known/oauth-authorization-server`,
`/oauth/register`, `/oauth/authorize`, `/oauth/token`. With OAuth on, a 401 (and a 429) from `/mcp` carries
`WWW-Authenticate: Bearer resource_metadata="<origin>/.well-known/oauth-protected-resource"`. Every authorization
response (code, `access_denied` or error) carries `iss=<origin>` (RFC 9207), and the metadata advertises it.

**The consent flow.** Claude opens `/oauth/authorize` in your browser:

1. The page names the requesting client, the first characters of its id and how long ago it registered, and the
   host the result goes back to, and asks for one of your **device tokens**. Type it only when the address bar shows
   your own server: it is checked there and never given to the client. The recovery key is not accepted; wrong
   tokens count against the failed-auth limit. **Continue only if you pressed Connect in your own Claude account a
   moment ago**: a link someone sends you opens this same genuine page, and approving it connects *their* account.
   A connector you just added shows a client registered seconds ago.
2. You see the vault's profiles (name, `user@host:port`, description; never secrets), **none selected**. Tick the
   ones this connector may use, name the grant and choose a lifetime (1, 7, 30 or 90 days; default 30). The form
   posts the positions of the ticked profiles, so even 1000 long names stay within the 64 KiB form limit. The label
   must not look like a grant id (8 hex digits) or a token (`sshp_...`), so `revoke-grant <id|label>` is never
   ambiguous.
3. **Allow** creates the grant and sends Claude an authorization code; **Deny** sends `access_denied`. The approval
   page expires after 5 minutes and works once. Each time it is shown again (after an error, say) it carries a new
   form token, and submitting an earlier copy ends the approval: its boxes point into the list as it was then. A
   ticked profile that was renamed or changed (target, credentials, anything) after the page was shown is refused
   ("The saved profiles changed meanwhile"), so what is granted is what you saw. Revoking the device whose token you typed ends its approval pages at once (the unlocked vault key is
   dropped from memory at the next sweep at the latest).

**What a grant is.** A separate mini-vault: its own random key and its own AES-256-GCM blob holding a **copy** of the
chosen profiles (with their passwords, keys and host-key pins). The main vault key is never wrapped for a grant, so
no connector token can decrypt any other profile. Codes, access tokens (1 hour) and refresh tokens (rotated on every
use, valid until the grant expires) each wrap the grant's key exactly like a device token wraps the vault key. A
running server, with or without `--oauth`, removes expired tokens and grants (and retry responses past their 60 s,
see Revocation) from the file at its next sweep (every 30 s), so a copy of the file taken later cannot be opened
with an expired token.

| A connector session can | It cannot |
|---|---|
| List and connect to the granted profiles; run commands, transfer files, use temp files and background jobs like a device session | See any other profile, or the vault's device list |
| Store a host-key pin on a granted profile's first connection (into the grant's own copy) | Add, change or remove profiles (`ssh_server_*`), or touch proxies (`ssh_proxy_set/enable/disable`): not listed and refused |
| | Use anything a remote device session cannot (`ssh_upload`, `ssh_temp_path`, raw `ssh_connect`) |

A grant is a **snapshot**: a password, key or profile you change or add later does not reach it, and
`vault pin-host-key` changes the main vault only. Connect again (remove and re-add the connector) to pick up changes,
then revoke the previous grant: re-adding does not end it, and its refresh token keeps the old profile set until it
expires (`vault list-grants`, then `vault revoke-grant <old id>`; at most 16 grants exist at once).
The audit log shows connector calls as `device=grant:<label>`.

**Revocation.** `mcp-sshpilot vault list-grants` shows id, label, client, approving device, created, expires and
profile count (no unlock key needed; profile names of a grant are encrypted). `vault revoke-grant <id|label>` deletes it at once: its tokens
stop working and its sessions end on the server's next request. An expired grant ends its sessions the same way.
Presenting an already used authorization code or an already rotated refresh token revokes the whole grant (one of
them leaked). So does a refresh token that names a live grant, comes with that grant's client id and matches none of
its tokens: only the last 8 spent codes and refresh tokens are remembered, and whoever rotates a stolen refresh token
more often than that must not make the real one look merely unknown. Such a request needs no secret, so it never waits
for the vault lock: while another process (a CLI command) holds it, the request is refused at once and counts as a
failed attempt, and the server's sweep (every 30 s) revokes the grant once the lock is free (a restart before that
forgets it; the next such request decides again).

Refresh rotation is idempotent for 60 s, so a flaky network does not cost you the grant: the refresh token rotated
last, presented again by its own client within 60 s while the token issued in its place has not been rotated itself
(a lost response, two refreshes racing, a server restart in between), gets the same access and refresh token back:
no new tokens, no vault write, `expires_in` counted from the retry. For that minute the response sits in the rotated
token's spent entry, sealed under a key derived from that token's own secret, and it leaves the file at the next
write or sweep. Any other presentation of a rotated refresh token revokes the grant: later than 60 s, after the token
issued in its place was rotated, from another client id, or with the server's clock stepped back since the rotation.
Every retry served is logged (`oauth grant refresh retry grant=<id> ip=<address>`). A connector needs one now and
then; retry lines at rotation after rotation of one grant mean that a second holder of its refresh token refreshes in
step with the connector (see the threat model), so revoke that grant.
A refused code or refresh token that the grant recognises (a replay, a late retry, the wrong client or token kind) is
never counted by the failed-auth limit and never answered with 429; only unknown ones count.
`vault rotate` removes every grant and client. `vault revoke-device` also removes the grants
that device approved (a stolen device token could have minted one) and names them; `--keep-grants` keeps them, and
`list-grants` then shows their device as `(revoked)`. Caps: 16 grants, 8 live tokens per grant, 8 sessions for all
grants together (so devices always keep room).

**Client registration stores nothing and writes nothing.** The `client_id` is self-contained: client name, digests of
its redirect URIs, issue time and a nonce, under an HMAC with a random per-vault key. `vault init` creates that key,
`vault rotate` replaces it (every client id issued before stops verifying), and `serve --oauth` adds it once to a
vault made before the key existed. A registration only reads it: no vault write, no lock (without a key it answers
503 with `Retry-After`). The server verifies the id on `/oauth/authorize`, accepting exactly what a registration can
produce (a cleaned name of 1-64 characters, 1-8 redirect URI digests, an issue time at most 60 s ahead of its clock,
in registration's own encoding), and keeps a client entry only alongside a grant, for `list-grants`. A `client_name`
that is not a string is refused with `invalid_client_metadata`. Anonymous registrations therefore cost no vault write
and share no budget with your connector: a valid registration always succeeds, and only refused ones (bad redirect
URI, bad metadata, too large) count against a limit of 20 per IP (IPv6 /64) and hour. An unexpected failure on the
OAuth endpoints (an unreadable vault, say) is logged at most once a minute, with a count, however often it is hit.

**What the client-id key gives whoever holds it.** The key sits in `vault.json` in clear: it encrypts nothing, so
every copy of the file (a backup, a revoked device's copy) hands it out. With it someone can mint client ids offline
that this server accepts like registered ones: any name a registration could produce, the digests of any redirect
URIs, and an issue time of their choosing (up to 60 s ahead), so the consent page shows whatever "registered ... ago"
they like. That is all it gains over an anonymous registration, which anyone may make: it saves the request and
picks the registration time (registering right before sending a link shows "seconds ago" too). It does not get past
the redirect allowlist, which every authorization request checks again; it cannot produce a code, which still needs
your device token typed on your own server's page; it opens no profile, token or grant; and it cannot store a client
entry the vault would refuse to read back (every write is validated before it lands). `vault rotate` retires it.

---

## How the vault works

```
vault.json
├── vault        AES-256-GCM(DEK, profiles JSON), AAD "mcp-sshpilot-vault-v1", fresh nonce on every write
├── devices[]    id, name, sha256(token secret), salt, AES-256-GCM(KEK_device, DEK) with AAD = device id
├── recovery     salt, AES-256-GCM(KEK_recovery, DEK) with AAD "recovery"
├── clientKey    HMAC key of the self-contained OAuth client ids, in clear (what it gives: see Client registration)
├── clients[]    the OAuth client of each grant (id, name, redirect URI): nothing secret
└── grants[]     id, label, client, expiry, profile count,
                 AES-256-GCM(GDEK, chosen profiles) with AAD "mcp-sshpilot-grant-v1:<id>",
                 tokens[]: kind, sha256(secret), salt, AES-256-GCM(KEK_token, GDEK) with AAD "grant:<id>:<kind>"
                 (a spent one keeps only its hash; a rotated refresh token also its time and successor's hash, and
                 for 60 s its rotation's response: salt, AES-256-GCM(HKDF-SHA256(its secret, salt,
                 "mcp-sshpilot-refresh-retry-v1"), access + refresh token + expiry) with AAD "grant:<id>:refresh-retry")

KEK = HKDF-SHA256(token secret, salt, "mcp-sshpilot-kek-v1")
device token  = sshp_<8 hex id>_<base64url(32 random bytes)>
recovery key  = sshp_recovery_<base64url(32 random bytes)>
grant token   = sshp_g<8 hex grant id>_<base64url(32 random bytes)>     (code, access or refresh)
```

- The DEK (data key) exists in server memory only inside a live MCP session, unwrapped with that request's
  token. It is zero-filled when the session closes (idle timeout, DELETE, revocation, shutdown).
- Token check: constant-time comparison of `sha256(secret)`; unknown ids cost the same work as known ones.
- The recovery key is for administration only (adding devices, `vault rotate`); it is not accepted over HTTP.
- Writes are atomic and durable (temp file, fsync, rename, directory fsync; mode 0600) under a cross-process lock,
  and re-read the file first so a device added or revoked by the CLI while the server runs is never lost or
  resurrected. The lock file names its owner (pid and host): a process only removes its own lock; a lock older
  than 30 s is broken only when its holder is not a live process on this host (another host or container cannot
  be asked, so there the age decides), breaking is serialized so two waiters cannot both take it, and a holder
  whose lock was broken meanwhile writes nothing.
- A write keeps the vault's file owner: run as root it hands the new file to the previous owner, run as any other
  user than the owner it is refused, so the server can always read its own vault.
- New secrets (recovery key, device tokens) are written to their destination (`--out` file and its directory
  entry, fsynced; or stdout, fsynced when redirected to a file) before the vault change is committed; if that
  write fails, the vault is left unchanged.
- Profiles written through the server are capped: 1000 profiles, 4 MiB in total, and per-field limits (a private key
  up to 32 KiB, a description up to 4 KiB).

## Threat model

**Protected against**

| Threat | Why |
|---|---|
| Theft of the disk, a backup or a VM snapshot | The vault is ciphertext; no key on disk can open it. |
| A stolen token, after you revoke the device | The device entry (its hash and its wrap of the DEK) is gone; its live sessions are closed on the next request to the server, and a request whose body was still arriving is checked again before it runs. |
| A leaked recovery key | `vault rotate` issues a new recovery key and re-keys the vault; the old key opens neither the new vault nor any later copy. |
| Network attackers | TLS (Caddy or native), plain HTTP refused off-loopback unless forced. |
| Token guessing | 256-bit secrets. Failed attempts are also limited per IP (IPv6: per /64), 10 per 5 minutes, then 429; a valid token is always accepted, so a client sharing your address cannot lock you out. A request without a bearer token is no guess and is not counted, and with OAuth on any grant-shaped token gets the plain 401 and is not counted either: connectors share Anthropic's egress addresses with every other Claude user, a 429 there would keep the connector from refreshing, and answering an unknown grant id differently from a known one would tell which grants exist. At the token endpoint only unknown codes and refresh tokens count. |
| A malicious web page in your browser (DNS rebinding, CSRF) | Any request carrying an `Origin` header that is not explicitly allowed gets 403; no CORS headers otherwise. |
| One device hijacking another's session | A session id works only with the token of the device that opened it; others get the same 404 as for an unknown id. |
| The model reading or exfiltrating the server's own files | Remote mode hides `ssh_upload` (local path) and `ssh_temp_path`; temp files live in a private per-session directory. |
| The model connecting with arbitrary raw credentials | `ssh_connect` is disabled remotely; only saved profiles, with pinned host keys. |
| The model steering a stored password somewhere else | A route change keeps the pin; on a profile not pinned yet it removes the stored password. Only the owner re-pins (below). |
| The model reaching the server's loopback services or cloud metadata | Profiles and proxies pointing at the MCP host's loopback, link-local or cloud-metadata addresses (169.254.169.254, 100.100.100.200, fd00:ec2::254) are refused; checked on the resolved address that is then dialed. |
| A swapped or MITM'd SSH server | Host key pinning (below): a different key aborts the handshake before any password or key is sent. |
| Secrets in logs | Audit lines carry time, device name, session id prefix, tool name, target and duration. Never arguments, command text, tokens or passwords. |
| Phishing for a device token through the consent page | The token is typed only on your own server's page (it names the host); a client can register only allowlisted redirect URIs, an unknown client or redirect URI gets an error page and never a redirect, and the page cannot be framed or posted to from another origin. |
| A stolen connector access or refresh token | It opens only the grant's copy of the profiles you ticked, never the main vault key; access tokens live 1 hour (and leave the file at the next sweep), the grant at most 90 days, `vault revoke-grant` ends it at once, and a replayed code or rotated refresh token revokes the grant, however often the thief rotated meanwhile (except a retry inside the 60 s window, which a thief refreshing in step with the connector can repeat at every rotation: see below). |
| A stolen device token used to mint a connector grant | `vault revoke-device` removes the grants that device approved together with it (unless `--keep-grants`), and `vault list-grants` shows which device approved each grant. |
| Anonymous registrations locking out your connector, or flooding the disk with vault rewrites | A registration stores nothing (self-contained, HMAC-verified client id), never writes the vault nor waits for its lock, and a valid one always succeeds; only refused registrations are limited, 20 per IP and hour. A code or refresh token that matches no entry of the grant it names, or an entry of another kind, is refused from a cached read, without the vault lock, with one exception: an unknown refresh token sent with the grant's own client id revokes the grant (see Revocation), and while another process holds the lock it is refused at once and counted, and the revocation is left to the server's sweep. A code or refresh token the grant does recognise takes the lock whatever client id comes with it (any attempt spends a code). |

**Not protected against**

| Threat | Notes |
|---|---|
| Root (or the service user) on the live host while a session is open | The DEK and decrypted profiles are in process memory then. Run the server on a box you trust as much as the SSH servers it reaches. |
| A compromised client device | Its token is in the MCP client config (for Claude Code: `~/.claude.json`). Revoke the device. |
| The agent itself | A connected agent can do whatever the profiles allow: run commands, read and write files, add its own key to a server. The dangerous-command and delete confirmations still apply, but they are a seatbelt for mistakes, not a security boundary. |
| A network attacker on a profile's first connection | Pinning is trust on first use: whoever answers the very first connection over the stored route gets pinned (and receives the password). Pin keys you have verified with `vault pin-host-key` before first use when that matters. Profiles imported from a `servers.json` used in stdio mode keep the pins they already have. |
| Other hosts on private networks, and the host's other addresses | Only the ranges above are refused. Private ranges stay reachable because your servers may live there; in the Docker deployment the compose network holds nothing but Caddy. The MCP host's own LAN or public address and the Docker gateway (172.17.0.1) are not recognised as "itself", and behind a proxy the target is resolved by the proxy, so only the proxy's address is checked: do not run an open SOCKS/HTTP proxy on the MCP host or its private network. |
| A revoked device that kept a copy of `vault.json` | Its old wrap of the DEK still opens that old copy (and any later copy until you rotate). See below. |
| A compromise on Anthropic's side (or of your Claude account) | Connector tokens live in Anthropic's cloud. Whoever controls them can use the granted profiles until the grant expires or you revoke it. Grant only what a connector needs, for as short as practical. |
| A consent link someone sends you, and OAuth mix-up | The link (or a malicious connector that points Claude at your authorization endpoint) opens the genuine consent page on your own server, so the "check the address bar" rule passes; approving connects the other party's client. Mitigations only: both pages warn against forwarded links and show the client id and how long ago it registered (a connector you just added registered seconds ago), and authorization responses carry `iss` (RFC 9207), which a client that checks it uses to detect a mix-up. Approve only a connection you started yourself a moment ago. |
| Someone who saw a connector token of a grant (its id is in every token) and knows the client id | They can end that grant by presenting a made-up refresh token for it: the price of revoking on an unknown refresh token (see Revocation). They cannot use the grant. A holder of a valid refresh token can also make the server rewrite the vault once per refresh (a retry inside the window writes nothing). |
| A stolen refresh token used in step with the connector, or a just-rotated one plus a copy of `vault.json` taken in that minute | The price of the idempotent retry: presented with the grant's client id inside the window, the rotated token gets the same access and refresh token the rotation returned, so whoever presents it second holds the live pair too, and the file copy decrypts that same response offline. Nothing is revoked then. The theft shows (the grant is revoked) once either side presents a rotated refresh token outside its window, i.e. when the two refresh more than 60 s apart. A thief who refreshes within 60 s of the connector at every rotation (it knows when the shared access token expires) is never revoked and shares the grant for as long as it keeps that up. What it cannot avoid is a retry at every rotation, and each one is logged (`oauth grant refresh retry`): revoke a grant that shows them rotation after rotation, or whose refresh token may have leaked. |
| A copy of `vault.json` (its client-id key and its grant list) | The client-id key lets the holder mint client ids the server accepts as registered, with a registration time of their choosing; the key gives nothing beyond what an anonymous registration gives (see Client registration). The file also lists every grant's id with its client id in clear, so the holder can end any live grant at will without any token: the denial of service described above for someone who saw a connector token. It can use no grant. `vault rotate` replaces the key and removes every grant. |
| Grants kept with `revoke-device --keep-grants` | Such a grant does not depend on the device that approved it; revoke it separately when in doubt. |

## Revocation and rotation

`vault revoke-device <id|name>` removes the device entry. The token stops working immediately, and live sessions
of that device are closed on the server's next request (and at the latest by the 30-second sweep). Connector grants
that device approved are removed with it, and their sessions end the same way; pass `--keep-grants` to keep them.

What revocation cannot do: the revoked device may have had the DEK, and if it also obtained a copy of
`vault.json` (it never gets the file through the API, but think backups, a shared disk), it can still decrypt
that copy. The DEK can only be changed by re-wrapping it for every device, which needs every device's token,
and the server never stores those. So the honest answer is:

```bash
mcp-sshpilot vault rotate --out ./recovery.new    # needs the current recovery key; writes the new one
```

`rotate` generates a new DEK, re-encrypts the profiles, **issues a new recovery key** (printed once, or written to
`--out <file>`; the old one stops working) and **removes every device**. Add your devices again
(`vault add-device`, with the new recovery key) and update their client configs. Rotating is also the answer to
a leaked recovery key. If the leaked profiles held passwords or keys, rotate those on the SSH servers too: no
vault feature can un-leak a password.

## Why bearer tokens, not mTLS

- Every MCP client supports a custom `Authorization` header; client certificates are supported by few, and
  not at all behind most TLS-terminating proxies without extra plumbing.
- The token is also key material: it unwraps the vault key. A client certificate would only authenticate, and
  the server would then have to keep a vault key on disk, losing the backup/snapshot protection.
- Revocation is one CLI command with immediate effect; no CRL/OCSP.

TLS still protects the token in transit. Treat a token like an SSH private key.

## Host key pinning (both modes)

The first `ssh_connect_profile` to a profile pins the server's host key (`SHA256:...`, the same format
`ssh-keygen -lf` prints) into the profile and says so in the result. Later connections, including automatic
reconnects, must present the same key; a different key aborts the handshake before authentication, so no
password or key is sent, and the error tells the agent to stop and report to the user rather than re-pin.

Changing a profile's host, port, username or proxy keeps the pin: the new route must lead to a server with the same
key (a port change on the same server keeps working), anything else is refused until the key is re-pinned.

Re-pinning a legitimately changed key, after checking it on the server itself:

- **Remote mode: only the owner, out of band.** The model cannot drop or set a pin (`reset_host_key` is not
  available). Run it where the live vault is, with an unlock key: on the server through the `vault` compose
  service, `docker compose run --rm vault pin-host-key <profile> SHA256:...` (natively:
  `mcp-sshpilot vault pin-host-key ...` with `MCP_SSHPILOT_VAULT` pointing at the served file), or `--clear` to let
  the next direct connection pin again. Never pin on an older copy and put it over the server's vault: that rolls
  back every revocation, rotation and pin made since the copy was taken.
- **stdio mode:** `ssh_server_update { name, reset_host_key: true }`, then `ssh_connect_profile`. Here the model
  can call it too; stdio clients normally ask you before a tool call.

Remote mode also keeps a stored password from following an unverified route. On a profile that is **not pinned
yet**: `ssh_server_update` changing host, port, username or proxy removes the stored password unless a new one is
passed in the same call; changing or removing the global proxy (`ssh_proxy_set` / `ssh_proxy_disable`,
`scope: "global"`) removes it from the profiles that inherit that proxy; and the first connection is refused while
a per-session proxy override is active (`ssh_proxy_set` runtime, `ssh_proxy_disable` runtime). Private keys are
kept: public-key authentication never hands the key itself to the server.

Raw `ssh_connect` sessions (stdio mode only) are not pinned, but their key is enforced on reconnect;
`ssh_status` reports them as not pinned. A changed key there is refused too; after checking it, `ssh_disconnect`
and connect again.

## Remote-mode tool surface

| Tool | Remote mode |
|---|---|
| `ssh_connect` | Disabled: only saved profiles. |
| `ssh_upload` | Disabled: `local_path` would be the server's filesystem. Use `ssh_write_file` or `ssh_temp_write` + `ssh_temp_upload`. |
| `ssh_temp_path` | Disabled: the local path is meaningless to a remote client. |
| `ssh_server_add` / `ssh_server_update` | Take the key inline as `privateKey` (validated, stored encrypted); `privateKeyPath` is refused. Note that a key passed this way travels through the model's context: prefer `vault init --import`. No `reset_host_key`. |
| `ssh_download_file`, `ssh_temp_*` | Per-session private directory, 64 MiB and 256 files per session (downloads in progress included), removed when the session ends. Downloads stream to disk; the preview shows at most 2 MiB. |
| `ssh_read_file`, `ssh_temp_read` | Return at most 2 MiB inline (JSON escaping can grow content up to 6x on the way out), and at most 8 MiB of inline content (download previews included) may be in flight per session, held until the result has been serialized. Read larger files in parts with `ssh_execute` (`head`, `tail`, `sed -n`). |
| `ssh_list_dir` | At most 10,000 entries (or 2 MiB of listing); the result says when it was cut. |
| `ssh_execute_background` | At most 32 jobs per session; the oldest finished job is dropped for a new one. |
| Dangerous-command / delete confirmations | At most 16 pending per kind (the oldest is dropped); a command held for confirmation is at most 64 KiB. |

Profiles are shared between all devices (it is one vault); SSH connections, background jobs, temp files, proxy
overrides and pending confirmations are per session.

## Limits and timeouts

| | Default |
|---|---|
| Request body | 8 MiB (413); 64 MiB of bodies being read at once across all sessions, past that 503 with `Retry-After: 1` |
| Command timeout | `timeout_ms` up to 1 hour (a running call keeps its session from the idle sweep and from eviction) |
| Unread responses | A response whose client stops reading for 60 s is dropped with its connection; a closed session drops its open responses |
| Requests in flight | 64 per device or grant (open GET streams included), 128 for all connector grants together (429) |
| Batches | One JSON-RPC request per POST (batches were removed from the MCP spec in 2025-06-18); a batch with more gets 400 |
| Temp store | 64 MiB per session and 256 MiB for all sessions together |
| Sessions | 4 per device or grant (its least recently used idle session is evicted), 8 for all connector grants together, 16 total (429) |
| Idle session | Closed after 30 min without requests and with no tool call running; an open GET event stream (or a POST stream that will never be answered) does not count. The client re-initializes. |
| Concurrent tool calls | 32 running calls per session; a cancelled call counts until its handler really ends. A POST that would exceed it gets 429; a request id that is still in flight in the session gets 400 |
| Failed auth | 10 per client IP (IPv6 /64) per 5 min, then further failures get 429 for the rest of the window; valid tokens always pass. Never counted: requests without a token, grant-shaped tokens on `/mcp` (with OAuth on), and refused codes or refresh tokens the server recognises at the token endpoint |
| Slow clients | Headers 10 s, whole request 60 s, keep-alive 5 s, 256 connections |

## Operational notes

- **Audit log** (stderr, one line per tool call):
  `2026-01-01T12:00:00.000Z audit device=laptop session=1a2b3c4d tool=ssh_execute target=deploy@203.0.113.10:22 ms=812 ok`.
  The line is written when the call's handler ends. The outcome is `ok`, `error`, `cancelled` (the client
  cancelled it; written when the handler ends, and the call may still have done its work on the server),
  `refused` (over the concurrent-call cap) or `aborted` (the session closed first).
- **Teardown:** closing a session or resetting a timed-out one ends the SSH connection and destroys its socket
  after 2 s even if the peer never closes its side, so pending SFTP requests fail and release what they held.
- **NAT:** the failed-auth limit is per IP. Clients behind the same NAT as an attacker may see 429 for a bad token,
  but a valid token always passes.
- **Memory (Docker):** temp stores share the 256 MiB `/tmp` tmpfs, which counts against the 1 GiB `mem_limit`;
  when it is full, downloads fail with "no space" instead of the container being OOM-killed. Raise both together.
- **Host header** validation is left to the reverse proxy (the Caddyfile serves only `$SSHPILOT_DOMAIN`).
- A vault write from the server can block it for up to 5 s while a CLI vault command holds the lock (CLI commands
  take milliseconds): a profile change, a consent approval, or a token request carrying a real code or refresh
  token. A request without a secret never waits for the lock (an unknown refresh token that would revoke its grant
  leaves that to the sweep). A CLI command stalled while holding it (suspended with Ctrl-Z, say) keeps its
  lock for as long as its process lives; profile writes fail with "locked by process N" until it ends.
- File modes (0600) are not enforced on Windows; protect the vault directory with NTFS ACLs there.
- **Backups:** back up `vault.json` freely, it is encrypted. Keep the recovery key separately, offline. Losing
  the recovery key and all device tokens means losing the profiles.
