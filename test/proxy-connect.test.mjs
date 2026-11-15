/* HTTP CONNECT tunnel against misbehaving proxies: none of them may crash the process or hang the handshake. */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";

/* The handshake deadline is 30 s; shrink it for this process only. */
const realSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...a) => realSetTimeout(fn, ms === 30_000 ? 300 : ms, ...a);
const { buildProxySocket } = await import("../dist/proxy.js");

const servers = [];
async function proxy(onConn) {
  const srv = net.createServer((s) => {
    s.on("error", () => {});
    onConn(s);
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  servers.push(srv);
  return { type: "http", host: "127.0.0.1", port: srv.address().port };
}
after(() => servers.forEach((s) => s.close()));

const tunnel = (p) => buildProxySocket(p, "example.com", 22);
const settle = (ms) => new Promise((r) => realSetTimeout(r, ms));

test("a reset after a refused CONNECT does not crash the process", async () => {
  const p = await proxy((s) => s.once("data", () => {
    s.write("HTTP/1.1 403 Forbidden\r\n\r\n");
    realSetTimeout(() => s.resetAndDestroy(), 50);
  }));
  await assert.rejects(tunnel(p), /HTTP CONNECT failed: HTTP\/1.1 403/);
  await settle(200);
});

test("a silent proxy hits the handshake deadline, then its reset is harmless", async () => {
  const p = await proxy((s) => realSetTimeout(() => s.resetAndDestroy(), 600));
  await assert.rejects(tunnel(p), /timeout/);
  await settle(500);
});

test("a proxy trickling bytes cannot stretch the handshake", async () => {
  const p = await proxy((s) => {
    const t = setInterval(() => s.write("x"), 50);
    s.on("close", () => clearInterval(t));
  });
  const started = Date.now();
  await assert.rejects(tunnel(p), /timeout/);
  assert.ok(Date.now() - started < 2000);
});

test("an endless header is cut at the size cap", async () => {
  const p = await proxy((s) => s.once("data", () => s.write("HTTP/1.1 200 OK\r\nX: " + "a".repeat(64 * 1024))));
  await assert.rejects(tunnel(p), /oversized response header/);
});

test("bytes sent together with the 200 reach the tunnel reader", async () => {
  const p = await proxy((s) => s.once("data", () => s.write("HTTP/1.1 200 Connection established\r\n\r\nSSH-2.0-test\r\n")));
  const sock = await tunnel(p);
  const got = await new Promise((resolve) => {
    sock.on("data", (d) => resolve(d.toString()));
    sock.resume();
  });
  assert.equal(got, "SSH-2.0-test\r\n");
  sock.destroy();
});
