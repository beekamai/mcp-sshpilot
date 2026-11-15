/* HTML of the OAuth consent flow (/oauth/authorize). Plain server-rendered forms: no JavaScript, no third-party
 * resources, one inline stylesheet allowed by its hash. Every dynamic string goes through esc(). */
import { createHash } from "crypto";
const STYLE = `
:root{color-scheme:light dark;--bg:#f6f3ee;--card:#fffdf9;--fg:#231f1a;--muted:#6b6259;--line:#e2dbd1;--accent:#9c4a2f;--accent-fg:#fff;--warn:#8a5a00;--warn-bg:#fdf3dc;--bad:#a12c2c;--bad-bg:#fbe6e3}
@media (prefers-color-scheme:dark){:root{--bg:#181512;--card:#221e1a;--fg:#eee7de;--muted:#a59a8e;--line:#3a332c;--accent:#d9825f;--accent-fg:#1b1410;--warn:#f0c46a;--warn-bg:#3a2e14;--bad:#f09a8f;--bad-bg:#3d1f1b}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:34rem;margin:0 auto;padding:24px 16px 40px}
h1{font-size:1.35rem;line-height:1.3;margin:0 0 4px}
.sub{color:var(--muted);margin:0 0 20px;font-size:.95rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 16px;margin:0 0 16px}
.card p{margin:0 0 10px}.card p:last-child{margin:0}
.host{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.92em;word-break:break-all;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:1px 6px}
.note{background:var(--warn-bg);color:var(--warn);border-radius:10px;padding:12px 14px;margin:0 0 16px;font-size:.93rem}
.err{background:var(--bad-bg);color:var(--bad);border-radius:10px;padding:12px 14px;margin:0 0 16px;font-weight:600}
label{display:block;font-weight:600;margin:0 0 6px}
input[type=password],input[type=text],select{width:100%;font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px 12px;min-height:44px}
input:focus-visible,select:focus-visible,button:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.field{margin:0 0 16px}
fieldset{border:0;margin:0 0 16px;padding:0}
legend{font-weight:600;margin:0 0 8px;padding:0}
.profile{display:flex;gap:12px;align-items:flex-start;padding:12px;border:1px solid var(--line);border-radius:10px;margin:0 0 8px;font-weight:400;cursor:pointer;background:var(--bg)}
.profile input{width:20px;height:20px;margin:2px 0 0;flex:none;accent-color:var(--accent)}
.profile b{display:block;word-break:break-word}
.profile span{display:block;color:var(--muted);font-size:.9rem;word-break:break-all}
.actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:20px}
button{font:inherit;font-weight:600;min-height:44px;padding:10px 18px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer;flex:1 1 140px}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-fg)}
.small{color:var(--muted);font-size:.85rem;margin:16px 0 0}
`;
/** CSP source for the one inline stylesheet every page carries. */
export const CONSENT_STYLE_SRC = `'sha256-${createHash("sha256").update(STYLE, "utf-8").digest("base64")}'`;
export function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => (({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }) as Record<string, string>)[c]);
}
function page(title: string, body: string): string {
    return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="same-origin"><meta name="robots" content="noindex,nofollow">
<title>${esc(title)}</title><style>${STYLE}</style></head>
<body><main>${body}</main></body></html>`;
}
const hidden = (fields: Record<string, string | undefined>): string => Object.entries(fields)
  .filter(([, v]) => v !== undefined)
  .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v as string)}">`)
  .join("");
export interface ConsentContext {
  clientName: string;
  /** First characters of the client id, and how long ago it registered ("40 seconds ago"). */
  clientId: string;
  registered: string;
  /** Host the code will be sent to (from the redirect URI). */
  redirectHost: string;
  /** Host of this server (from --public-url): the only place the device token is ever typed. */
  serverHost: string;
}
function intro(c: ConsentContext): string {
    return `<h1>Connect ${esc(c.clientName)} to mcp-sshpilot</h1>
<p class="sub">on <span class="host">${esc(c.serverHost)}</span></p>
<div class="card"><p><b>${esc(c.clientName)}</b> asks for access to SSH profiles saved on this server.</p>
<p>If you approve, it is sent back to <span class="host">${esc(c.redirectHost)}</span>.</p>
<p class="small">Client <span class="host">${esc(c.clientId)}</span>, registered ${esc(c.registered)}.</p></div>
<div class="note"><b>Continue only if you pressed Connect in your own Claude account in the last few minutes.</b>
If someone sent you this link, press Deny or close the page: approving would connect their account to your servers.</div>`;
}
/** Step 1: the owner proves who they are with a device token. */
export function tokenPage(c: ConsentContext, oauthParams: Record<string, string | undefined>, error?: string): string {
  return page("Connect: sign in", `${intro(c)}
${error ? `<div class="err" role="alert">${esc(error)}</div>` : ""}
<div class="note">Type a device token only on a page whose address bar shows <span class="host">${esc(c.serverHost)}</span>.
It is checked here and never passed to ${esc(c.clientName)}. The recovery key is not accepted.</div>
<form method="post" action="/oauth/authorize" autocomplete="off">
${hidden(oauthParams)}
<div class="field"><label for="device_token">Device token</label>
<input id="device_token" name="device_token" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" required></div>
<div class="actions"><button class="primary" type="submit">Continue</button></div>
</form>
<p class="small">Next you choose which profiles this connection may use. Nothing is shared before that.</p>`);
}
export interface ProfileChoice {
  name: string;
  target: string;
  description?: string;
}
export const LIFETIME_DAYS = [1, 7, 30, 90] as const;
/** Step 2: pick profiles (none preselected), a label and a lifetime. */
export function selectPage(
  c: ConsentContext,
  form: { pending: string; csrf: string; label: string; lifetimeDays: number; deviceName: string },
  profiles: ProfileChoice[],
  selected: Set<string>,
  error?: string,
): string {
  const items = profiles
    .map((p, i) => `<label class="profile" for="p${i}"><input type="checkbox" id="p${i}" name="profile" value="${i}"${selected.has(p.name) ? " checked" : ""}>
<span><b>${esc(p.name)}</b><span>${esc(p.target)}</span>${p.description ? `<span>${esc(p.description)}</span>` : ""}</span></label>`)
    .join("\n");
  const options = LIFETIME_DAYS.map((d) => `<option value="${d}"${d === form.lifetimeDays ? " selected" : ""}>${d === 1 ? "1 day" : `${d} days`}</option>`).join("");
  return page("Connect: choose profiles", `${intro(c)}
${error ? `<div class="err" role="alert">${esc(error)}</div>` : ""}
<form method="post" action="/oauth/authorize">
${hidden({ pending: form.pending, csrf: form.csrf })}
<fieldset><legend>Profiles ${esc(c.clientName)} may use</legend>
${items || `<p class="sub">This vault has no saved profiles.</p>`}
</fieldset>
<div class="note">The grant gets a copy of the chosen profiles, including their passwords and keys, and can run any command
on those servers until it expires or you revoke it. It cannot see other profiles or change saved ones.</div>
<div class="field"><label for="label">Name of this grant</label>
<input id="label" name="label" type="text" maxlength="64" value="${esc(form.label)}"></div>
<div class="field"><label for="lifetime">Expires after</label><select id="lifetime" name="lifetime">${options}</select></div>
<div class="actions"><button class="primary" type="submit" name="action" value="grant">Allow</button>
<button type="submit" name="action" value="deny">Deny</button></div>
</form>
<p class="small">Approved with device "${esc(form.deviceName)}". Revoke later with <span class="host">mcp-sshpilot vault revoke-grant</span>.</p>`);
}
/** Dead end: shown instead of redirecting whenever the redirect target itself cannot be trusted. */
export function errorPage(title: string, message: string): string {
  return page(title, `<h1>${esc(title)}</h1><div class="card"><p>${esc(message)}</p></div>
<p class="small">Nothing was shared. Start the connection again from the client.</p>`);
}
