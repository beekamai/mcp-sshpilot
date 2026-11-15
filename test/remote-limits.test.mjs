/* Remote mode: memory a slow or greedy authenticated client can pin stays bounded. */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { request } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createVault, addDevice } from "../dist/vault.js";
import { startHttpServer } from "../dist/http.js";
import { createMcpServer } from "../dist/mcp-server.js";
import { clampTimeout, REMOTE_MAX_EXEC_TIMEOUT_MS } from "../dist/ssh-core.js";

const MiB = 1024 * 1024;
let dir, token, srv;

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "sshpilot-limits-"));
  const vaultPath = join(dir, "vault.json");
  const { recoveryKey } = createVault(vaultPath, { servers: [] });
  token = addDevice(vaultPath, "pc", recoveryKey).token;
  srv = await startHttpServer({
    vaultPath,
    buildServer: createMcpServer,
    port: 0,
    handleSignals: false,
    log: () => {},
    limits: { maxBodyBytes: MiB, maxBodyBytesTotal: 1.5 * MiB },
  });
});

after(async () => {
  await srv?.close();
  rmSync(dir, { recursive: true, force: true });
});

/* Opens a POST that declares `length` bytes and sends only `sent` of them; resolves with the status if one arrives. */
function slowPost(length, sent) {
  const req = request({
    host: "127.0.0.1",
    port: srv.port,
    path: "/mcp",
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "content-length": String(length),
    },
  });
  const status = new Promise((resolve) => {
    req.on("response", (res) => { res.resume(); resolve(res.statusCode); });
    req.on("error", () => resolve(null));
  });
  req.write(Buffer.alloc(sent, 0x20));
  return { req, status };
}

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const stillReading = (p) => Promise.race([p.status, wait(300).then(() => "reading")]);

test("parallel slow bodies past the shared budget get 503, not memory", async () => {
  const first = slowPost(MiB, 0.9 * MiB);
  await wait(150);
  const second = slowPost(MiB, 0.9 * MiB);
  assert.equal(await second.status, 503);
  second.req.destroy();
  first.req.destroy();
});

test("the budget is released when a slow client goes away", async () => {
  const first = slowPost(MiB, 0.9 * MiB);
  await wait(150);
  first.req.destroy();
  await wait(150);
  const next = slowPost(MiB, 0.9 * MiB);
  assert.equal(await stillReading(next), "reading", "a fresh body fits again");
  next.req.destroy();
});

test("declared but unsent bodies hold no budget, so they cannot lock out the owner", async () => {
  const idle = Array.from({ length: 6 }, () => slowPost(MiB, 0));
  await wait(150);
  const ok = slowPost(512 * 1024, 512 * 1024);
  ok.req.end();
  /* 400: the padding is not JSON. Anything but 503 shows the body was read in full. */
  assert.equal(await ok.status, 400);
  idle.forEach((p) => p.req.destroy());
});

test("remote exec timeout is capped at one hour", () => {
  assert.equal(clampTimeout(2e9, REMOTE_MAX_EXEC_TIMEOUT_MS), REMOTE_MAX_EXEC_TIMEOUT_MS);
  assert.equal(clampTimeout(5_000, REMOTE_MAX_EXEC_TIMEOUT_MS), 5_000);
  assert.equal(clampTimeout(2e9), 2e9);
});
