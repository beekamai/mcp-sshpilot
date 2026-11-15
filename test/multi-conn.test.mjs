/* Several SSH connections per session: parallel subagents of one client must neither block nor retarget each other. */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createCtx, destroyCtx, STDIO_MAX_CONNECTIONS, REMOTE_MAX_CONNECTIONS } from "../dist/state.js";
import { handleToolCall } from "../dist/handlers.js";
import { withDeadline, runScript, findConn } from "../dist/ssh-core.js";
import { startSshServer, memoryStore, profile, text, wait } from "./multi-conn-fixture.mjs";

let a, b;

before(async () => {
  a = await startSshServer("A", { "/data.bin": Buffer.from([0, 1, 2, 3, 250, 251]), "/notes.txt": "hello" });
  b = await startSshServer("B");
});

after(async () => {
  await a?.close();
  await b?.close();
});

function stdioCtx(store = memoryStore([profile("alpha", a), profile("Beta", b)])) {
  return createCtx({ store, mode: "stdio" });
}

const call = (ctx, name, args = {}) => handleToolCall(ctx, name, args);

test("connection caps are exported", () => {
  assert.equal(STDIO_MAX_CONNECTIONS, 16);
  assert.equal(REMOTE_MAX_CONNECTIONS, 4);
});

test("two connections in one ctx run commands concurrently, each on its own server", async () => {
  const ctx = stdioCtx();
  try {
    const started = Date.now();
    const [ra, rb] = await Promise.all([
      call(ctx, "ssh_execute", { profile: "alpha", command: "delay:400:x" }),
      call(ctx, "ssh_execute", { profile: "beta", command: "delay:400:y" }),
    ]);
    assert.ok(!ra.isError, text(ra));
    assert.ok(!rb.isError, text(rb));
    assert.match(text(ra), /x@A/);
    assert.match(text(rb), /y@B/);
    assert.ok(Date.now() - started < 790, `ran in parallel (${Date.now() - started} ms)`);
    assert.equal(ctx.connections.size, 2);
    /* Case-insensitive like getServerProfile; the saved spelling names the connection. */
    assert.ok(findConn(ctx, "beta").name === "Beta");
    const status = text(await call(ctx, "ssh_status"));
    assert.match(status, /Connection: alpha/);
    assert.match(status, /Connection: Beta/);
  } finally {
    destroyCtx(ctx);
  }
});

test("parallel first use of one profile opens one connection", async () => {
  const ctx = stdioCtx();
  const before = a.connections;
  try {
    const rs = await Promise.all([1, 2, 3].map((i) => call(ctx, "ssh_execute", { profile: "alpha", command: `echo:${i}` })));
    for (const r of rs) assert.ok(!r.isError, text(r));
    assert.equal(a.connections - before, 1);
  } finally {
    destroyCtx(ctx);
  }
});

test("omitted profile with two connections is refused and nothing runs", async () => {
  const ctx = stdioCtx();
  try {
    await call(ctx, "ssh_connect_profile", { profile_name: "alpha" });
    await call(ctx, "ssh_connect_profile", { profile_name: "Beta" });
    const na = a.commands.length;
    const nb = b.commands.length;
    const r = await call(ctx, "ssh_execute", { command: "echo:who" });
    assert.equal(r.isError, true);
    assert.match(text(r), /alpha/);
    assert.match(text(r), /Beta/);
    assert.match(text(r), /Nothing was executed/);
    assert.equal(a.commands.length, na);
    assert.equal(b.commands.length, nb);
    const d = await call(ctx, "ssh_disconnect");
    assert.equal(d.isError, true);
    assert.equal(ctx.connections.size, 2);
    assert.match(text(await call(ctx, "ssh_disconnect", { profile: "BETA" })), /Disconnected from Beta/);
    assert.match(text(await call(ctx, "ssh_execute", { command: "echo:only" })), /only@A/);
  } finally {
    destroyCtx(ctx);
  }
});

test("single connection works without profile, as before", async () => {
  const ctx = stdioCtx();
  try {
    assert.match(text(await call(ctx, "ssh_connect_profile", { profile_name: "alpha" })), /pinned host key/);
    assert.match(text(await call(ctx, "ssh_execute", { command: "echo:solo" })), /solo@A/);
    assert.match(text(await call(ctx, "ssh_disconnect")), /Disconnected/);
    const r = await call(ctx, "ssh_execute", { command: "echo:none" });
    assert.equal(r.isError, true);
    assert.match(text(r), /No active SSH connection/);
  } finally {
    destroyCtx(ctx);
  }
});

test("a confirmation runs only on the connection it was issued on", async () => {
  const ctx = stdioCtx();
  try {
    await call(ctx, "ssh_connect_profile", { profile_name: "alpha" });
    const held = text(await call(ctx, "ssh_execute", { command: "rm -rf /tmp/x" }));
    const id = /confirmation_id: "([^"]+)"/.exec(held)[1];
    await call(ctx, "ssh_connect_profile", { profile_name: "Beta" });
    const na = a.commands.length;
    const nb = b.commands.length;
    const wrong = await call(ctx, "ssh_execute_dangerous", { confirmation_id: id, confirm: true, profile: "Beta" });
    assert.equal(wrong.isError, true);
    assert.match(text(wrong), /only runs there/);
    assert.equal(a.commands.length, na);
    assert.equal(b.commands.length, nb);
    /* Omitted profile with two connections open: still runs, and on alpha. */
    const ok = await call(ctx, "ssh_execute_dangerous", { confirmation_id: id, confirm: true });
    assert.ok(!ok.isError, text(ok));
    assert.equal(a.commands.at(-1), "rm -rf /tmp/x");
    assert.equal(b.commands.length, nb);
  } finally {
    destroyCtx(ctx);
  }
});

test("a confirmation dropped by the pending cap says so", async () => {
  const ctx = stdioCtx();
  try {
    await call(ctx, "ssh_connect_profile", { profile_name: "alpha" });
    const ids = [];
    for (let i = 0; i < 17; i++) ids.push(/confirmation_id: "([^"]+)"/.exec(text(await call(ctx, "ssh_execute", { command: `rm -rf /tmp/${i}` })))[1]);
    const r = await call(ctx, "ssh_execute_dangerous", { confirmation_id: ids[0], confirm: true });
    assert.equal(r.isError, true);
    assert.match(text(r), /dropped: more than 16/);
    assert.ok(ctx.logs.some((e) => /Pending confirmation .* dropped/.test(e.content)));
    assert.match(text(await call(ctx, "ssh_execute_dangerous", { confirmation_id: "nope", confirm: true })), /not found or expired/);
  } finally {
    destroyCtx(ctx);
  }
});

test("profile connections keep no credentials, and reconnect by re-reading the profile", async () => {
  const ctx = stdioCtx();
  try {
    await call(ctx, "ssh_connect_profile", { profile_name: "alpha" });
    const conn = findConn(ctx, "alpha");
    for (const cfg of [conn.session.config, conn.lastConnect.config]) {
      assert.equal(cfg.password, undefined);
      assert.equal(cfg.privateKey, undefined);
      assert.equal(cfg.passphrase, undefined);
    }
    assert.equal(conn.session.client.config.password, undefined);
    a.dropClients();
    for (let i = 0; i < 50 && conn.session?.connected; i++) await wait(20);
    const r = await call(ctx, "ssh_execute", { command: "echo:back" });
    assert.ok(!r.isError, text(r));
    assert.match(text(r), /reconnected automatically/);
    assert.match(text(r), /back@A/);
  } finally {
    destroyCtx(ctx);
  }
});

test("reconnect is refused when the profile now points elsewhere", async () => {
  const store = memoryStore([profile("alpha", a)]);
  const ctx = stdioCtx(store);
  try {
    await call(ctx, "ssh_connect_profile", { profile_name: "alpha" });
    store.save({ servers: [{ ...store.cfg.servers[0], port: b.port }] });
    const conn = findConn(ctx, "alpha");
    a.dropClients();
    for (let i = 0; i < 50 && conn.session?.connected; i++) await wait(20);
    const nb = b.commands.length;
    const r = await call(ctx, "ssh_execute", { command: "echo:x" });
    assert.equal(r.isError, true);
    assert.match(text(r), /not reconnecting/);
    assert.equal(b.commands.length, nb);
  } finally {
    destroyCtx(ctx);
  }
});

test("stdin is logged by size, not content; logs are tagged per connection", async () => {
  const ctx = stdioCtx();
  try {
    await call(ctx, "ssh_execute", { profile: "alpha", command: "echo:1" });
    await call(ctx, "ssh_execute", { profile: "Beta", command: "echo:2" });
    const r = await runScript(findConn(ctx, "alpha"), "export TOKEN=supersecret\n");
    assert.equal(r.code, 0);
    const all = ctx.logs.map((e) => e.content).join("\n");
    assert.ok(!all.includes("supersecret"));
    assert.match(all, /\[alpha\] sh -s \[stdin: 25 bytes\]/);
    const onlyBeta = text(await call(ctx, "ssh_get_logs", { profile: "beta" }));
    assert.match(onlyBeta, /\[Beta\]/);
    assert.ok(!onlyBeta.includes("[alpha]"));
  } finally {
    destroyCtx(ctx);
  }
});

test("as_base64 returns the file inline; temp upload is bound to its connection", async () => {
  const ctx = stdioCtx();
  try {
    const r = await call(ctx, "ssh_download_file", { profile: "alpha", remote_path: "/data.bin", as_base64: true });
    assert.ok(!r.isError, text(r));
    assert.match(text(r), /Content \(base64\)/);
    assert.ok(text(r).includes(Buffer.from([0, 1, 2, 3, 250, 251]).toString("base64")));
    const bin = await call(ctx, "ssh_download_file", { profile: "alpha", remote_path: "/data.bin" });
    assert.match(text(bin), /BINARY: 6 bytes/);
    const [tf] = [...ctx.tempFiles.values()];
    assert.equal(tf.connection, "alpha");
    await call(ctx, "ssh_connect_profile", { profile_name: "Beta" });
    /* The fixture refuses SFTP writes: the error is logged on the connection that was asked. */
    const errors = (n) => ctx.logs.filter((e) => e.conn === n && e.type === "error").length;
    const before = errors("alpha");
    const up = await call(ctx, "ssh_temp_upload", { temp_id: tf.id, remote_path: "/x" });
    assert.equal(up.isError, true);
    assert.ok(errors("alpha") > before, "went back to alpha");
    assert.equal(errors("Beta"), 0, "never went to Beta");
  } finally {
    destroyCtx(ctx);
  }
});

test("disconnect all closes every connection", async () => {
  const ctx = stdioCtx();
  try {
    await call(ctx, "ssh_connect_profile", { profile_name: "alpha" });
    await call(ctx, "ssh_connect_profile", { profile_name: "Beta" });
    const r = text(await call(ctx, "ssh_disconnect", { all: true }));
    assert.match(r, /alpha/);
    assert.match(r, /Beta/);
    assert.equal(ctx.connections.size, 0);
  } finally {
    destroyCtx(ctx);
  }
});

test("the connection cap holds", async () => {
  const many = Array.from({ length: REMOTE_MAX_CONNECTIONS + 1 }, (_, i) => profile(`p${i}`, a, { hostKeySha256: a.fingerprint }));
  const ctx = createCtx({ store: memoryStore(many), mode: "remote", allowLocalTargets: true });
  try {
    for (let i = 0; i < REMOTE_MAX_CONNECTIONS; i++) {
      const r = await call(ctx, "ssh_connect_profile", { profile_name: `p${i}` });
      assert.ok(!r.isError, text(r));
    }
    const r = await call(ctx, "ssh_execute", { profile: `p${REMOTE_MAX_CONNECTIONS}`, command: "echo:x" });
    assert.equal(r.isError, true);
    assert.match(text(r), /connections are already open/);
  } finally {
    destroyCtx(ctx);
  }
});

test("a stalled connect is cut by the deadline, voided and forgotten", async () => {
  const ctx = createCtx({ store: memoryStore([]) });
  const conn = { name: "slow", key: "slow", ctx, session: null, lastConnect: null, gen: 0, connecting: new Promise(() => {}) };
  ctx.connections.set("slow", conn);
  await assert.rejects(withDeadline(() => conn, new Promise(() => {}), 30, "ssh_execute: connecting"), /timed out/);
  assert.ok(conn.gen > 0, "a late handshake sees a stale generation");
  assert.equal(conn.connecting, null);
  assert.equal(ctx.connections.size, 0, "a first connect leaves nothing to reconnect to");
});
