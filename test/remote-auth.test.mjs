/* Remote mode: what an internet client without (or with the wrong) credentials gets from /mcp. */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createVault, addDevice, revokeDevice } from "../dist/vault.js";
import { startHttpServer } from "../dist/http.js";
import { createMcpServer } from "../dist/mcp-server.js";

const SECRET = "Pl41nT3xt-Passw0rd-Never-On-Disk";
let dir, vaultPath, recovery, pc, laptop, srv, base;

const INIT = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "0" } },
};

function post(body, headers = {}) {
  return fetch(`${base}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers },
    body: JSON.stringify(body),
  });
}

async function rpcResult(res) {
  const text = await res.text();
  const ct = res.headers.get("content-type") ?? "";
  if (ct.includes("text/event-stream")) {
    const data = text.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trim());
    return JSON.parse(data.at(-1));
  }
  return JSON.parse(text);
}

async function openSession(token) {
  const res = await post(INIT, { authorization: `Bearer ${token}` });
  assert.equal(res.status, 200);
  const sid = res.headers.get("mcp-session-id");
  assert.ok(sid, "initialize returns a session id");
  await res.text();
  const h = { authorization: `Bearer ${token}`, "mcp-session-id": sid, "mcp-protocol-version": "2025-06-18" };
  (await post({ jsonrpc: "2.0", method: "notifications/initialized" }, h)).body?.cancel();
  return h;
}

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "sshpilot-test-"));
  vaultPath = join(dir, "vault.json");
  ({ recoveryKey: recovery } = createVault(vaultPath, {
    servers: [{ name: "prod", host: "203.0.113.10", username: "root", password: SECRET }],
  }));
  pc = addDevice(vaultPath, "pc", recovery).token;
  laptop = addDevice(vaultPath, "laptop", recovery).token;
  srv = await startHttpServer({
    vaultPath,
    buildServer: createMcpServer,
    port: 0,
    handleSignals: false,
    log: () => {},
    limits: { authFailLimit: 3 },
  });
  base = `http://127.0.0.1:${srv.port}`;
});

after(async () => {
  await srv?.close();
  rmSync(dir, { recursive: true, force: true });
});

test("vault file holds no plaintext secret or token", () => {
  const raw = readFileSync(vaultPath, "utf8");
  for (const s of [SECRET, recovery, pc, laptop]) assert.ok(!raw.includes(s));
});

test("healthz answers without auth and reveals nothing else", async () => {
  const res = await fetch(`${base}/healthz`);
  assert.equal(res.status, 200);
  assert.equal((await res.text()).trim(), "ok");
});

test("no token, malformed header and wrong token get 401", async () => {
  assert.equal((await post(INIT)).status, 401);
  assert.equal((await post(INIT, { authorization: `Basic ${pc}` })).status, 401);
  assert.equal((await post(INIT, { authorization: `Bearer ${pc.slice(0, -2)}xx` })).status, 401);
});

test("recovery key is not a session credential", async () => {
  assert.equal((await post(INIT, { authorization: `Bearer ${recovery}` })).status, 401);
});

test("browser origin is refused before auth", async () => {
  const res = await post(INIT, { authorization: `Bearer ${pc}`, origin: "https://evil.example" });
  assert.equal(res.status, 403);
});

test("brute force hits 429, the owner's valid token still passes", async () => {
  let limited = false;
  for (let i = 0; i < 10 && !limited; i++) {
    const res = await post(INIT, { authorization: `Bearer sshp_${"A".repeat(52)}` });
    limited = res.status === 429;
  }
  assert.ok(limited, "failed attempts are rate limited");
  const ok = await post(INIT, { authorization: `Bearer ${pc}` });
  assert.equal(ok.status, 200);
  await ok.text();
});

test("a session id cannot be used with another device's token", async () => {
  const h = await openSession(pc);
  const res = await post({ jsonrpc: "2.0", id: 2, method: "tools/list" }, { ...h, authorization: `Bearer ${laptop}` });
  assert.equal(res.status, 404);
});

test("remote tool surface has no raw connect, local upload or temp path", async () => {
  const h = await openSession(pc);
  const out = await rpcResult(await post({ jsonrpc: "2.0", id: 3, method: "tools/list" }, h));
  const names = out.result.tools.map((t) => t.name);
  for (const n of ["ssh_connect", "ssh_upload", "ssh_temp_path"]) assert.ok(!names.includes(n), n);
  assert.ok(names.includes("ssh_connect_profile"));
});

test("profile listing never returns stored secrets", async () => {
  const h = await openSession(pc);
  const call = { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "ssh_list_profiles", arguments: {} } };
  const out = JSON.stringify(await rpcResult(await post(call, h)));
  assert.ok(out.includes("prod"));
  assert.ok(!out.includes(SECRET));
});

test("revoked device is cut off on its next request", async () => {
  const h = await openSession(laptop);
  assert.ok(revokeDevice(vaultPath, "laptop"));
  const res = await post({ jsonrpc: "2.0", id: 5, method: "tools/list" }, h);
  /* 429 when the brute-force test above already limited this address: a revoked token is a failed attempt too. */
  assert.ok([401, 429].includes(res.status), String(res.status));
});
