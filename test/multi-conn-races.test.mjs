/* Interleavings found in review: voided connects, peers that hang up mid-handshake, arguments that must not be read
 * as "omitted", and bindings that must outlive a moved profile. */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, connect } from "node:net";
import { createCtx, destroyCtx } from "../dist/state.js";
import { handleToolCall, describeCallTarget } from "../dist/handlers.js";
import { sshConnect, withDeadline } from "../dist/ssh-core.js";
import { startSshServer, memoryStore, profile, text, wait, USER, PASSWORD } from "./multi-conn-fixture.mjs";

let a, b;

before(async () => {
  a = await startSshServer("A", { "/notes.txt": "hello" });
  b = await startSshServer("B");
});

after(async () => {
  await a?.close();
  await b?.close();
});

const call = (ctx, name, args = {}) => handleToolCall(ctx, name, args);

function listen(onSocket) {
  const srv = createServer(onSocket);
  return new Promise((resolve) => srv.listen(0, "127.0.0.1", () => resolve(srv)));
}

test("a voided first connect neither drops nor leaks the connection a retry opened", async () => {
  let first = true;
  const relay = await listen((sock) => {
    const delay = first ? 400 : 0;
    first = false;
    setTimeout(() => {
      const up = connect(a.port, "127.0.0.1");
      sock.pipe(up).pipe(sock);
      sock.on("error", () => up.destroy());
      up.on("error", () => sock.destroy());
    }, delay);
  });
  const ctx = createCtx({ store: memoryStore([]), mode: "stdio" });
  const cfg = { host: "127.0.0.1", port: relay.address().port, username: USER, password: PASSWORD };
  try {
    const slow = sshConnect(ctx, cfg);
    const key = [...ctx.connections.keys()][0];
    await assert.rejects(withDeadline(() => ctx.connections.get(key), slow, 100, "connect"), /timed out/);
    assert.equal(ctx.connections.size, 0, "the voided first connect is forgotten");
    await assert.rejects(slow, /superseded|closed/);
    const retry = await sshConnect(ctx, cfg);
    assert.ok(retry.conn.session?.connected);
    await wait(600);
    assert.equal(ctx.connections.size, 1);
    assert.equal(ctx.connections.get(key), retry.conn, "the retry's entry survives the late first attempt");
  } finally {
    destroyCtx(ctx);
    relay.close();
  }
});

test("a peer that hangs up after its banner fails the connect instead of hanging it", async () => {
  const fake = await listen((sock) => sock.end("SSH-2.0-Fake\r\n"));
  const ctx = createCtx({ store: memoryStore([]), mode: "stdio" });
  try {
    const started = Date.now();
    await assert.rejects(sshConnect(ctx, { host: "127.0.0.1", port: fake.address().port, username: USER, password: PASSWORD }));
    assert.ok(Date.now() - started < 5_000);
    assert.equal(ctx.connections.size, 0);
  } finally {
    destroyCtx(ctx);
    fake.close();
  }
});

test("an invalid profile argument is refused, not read as omitted", async () => {
  const ctx = createCtx({ store: memoryStore([profile("alpha", a)]), mode: "stdio" });
  try {
    await call(ctx, "ssh_connect_profile", { profile_name: "alpha" });
    const n = a.commands.length;
    for (const p of ["", "   ", 42, ["alpha"], { name: "alpha" }]) {
      const r = await call(ctx, "ssh_execute", { profile: p, command: "echo:x" });
      assert.equal(r.isError, true, JSON.stringify(p));
      assert.match(text(r), /profile must be a non-empty string/);
    }
    assert.equal(a.commands.length, n);
    assert.ok(!(await call(ctx, "ssh_execute", { profile: null, command: "echo:x" })).isError, "null counts as omitted");
  } finally {
    destroyCtx(ctx);
  }
});

test("a non-boolean confirm keeps the confirmation pending", async () => {
  const ctx = createCtx({ store: memoryStore([profile("alpha", a)]), mode: "stdio" });
  try {
    const held = text(await call(ctx, "ssh_execute", { profile: "alpha", command: "rm -rf /tmp/q" }));
    const id = /confirmation_id: "([^"]+)"/.exec(held)[1];
    const n = a.commands.length;
    const r = await call(ctx, "ssh_execute_dangerous", { confirmation_id: id, confirm: "true" });
    assert.equal(r.isError, true);
    assert.equal(a.commands.length, n);
    assert.ok(ctx.pendingConfirmations.has(id));
  } finally {
    destroyCtx(ctx);
  }
});

test("the audit target of a confirmed command is its own connection, after it ran", async () => {
  const ctx = createCtx({ store: memoryStore([profile("alpha", a), profile("beta", b)]), mode: "stdio" });
  try {
    const held = text(await call(ctx, "ssh_execute", { profile: "alpha", command: "rm -rf /tmp/z" }));
    const id = /confirmation_id: "([^"]+)"/.exec(held)[1];
    await call(ctx, "ssh_connect_profile", { profile_name: "beta" });
    const args = { confirmation_id: id, confirm: true };
    assert.ok(!(await call(ctx, "ssh_execute_dangerous", args)).isError);
    assert.equal(describeCallTarget(ctx, args, "ssh_execute_dangerous"), `u@127.0.0.1:${a.port}`);
  } finally {
    destroyCtx(ctx);
  }
});

test("ssh_temp_upload refuses to follow a profile that moved since the download", async () => {
  const store = memoryStore([profile("alpha", a)]);
  const ctx = createCtx({ store, mode: "stdio" });
  try {
    await call(ctx, "ssh_download_file", { profile: "alpha", remote_path: "/notes.txt" });
    const [tf] = [...ctx.tempFiles.values()];
    await call(ctx, "ssh_disconnect");
    store.save({ servers: [{ ...store.cfg.servers[0], port: b.port }] });
    const seen = b.connections;
    const r = await call(ctx, "ssh_temp_upload", { temp_id: tf.id });
    assert.equal(r.isError, true);
    assert.match(text(r), /now points at/);
    assert.equal(b.connections, seen, "nothing dialed the new endpoint");
  } finally {
    destroyCtx(ctx);
  }
});

test("remote allowTofu: an unpinned profile takes its stored route, even when the override is 'disabled'", async () => {
  const proxied = profile("proxied", a, { proxy: { type: "socks5", host: "127.0.0.1", port: 1 } });
  const ctx = createCtx({ store: memoryStore([proxied]), mode: "remote", allowLocalTargets: true, allowTofu: true });
  try {
    ctx.proxyOverride = { mode: "disabled" };
    const seen = a.connections;
    const r = await call(ctx, "ssh_connect_profile", { profile_name: "proxied" });
    assert.equal(r.isError, true);
    assert.match(text(r), /route stored in the vault/);
    assert.equal(a.connections, seen);
  } finally {
    destroyCtx(ctx);
  }
});
