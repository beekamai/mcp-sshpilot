/* Connection namespaces, credentials that must not travel or linger, and upload guards. */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCtx, destroyCtx } from "../dist/state.js";
import { FileProfileStore } from "../dist/config.js";
import { handleToolCall } from "../dist/handlers.js";
import { findConn, keysOfName } from "../dist/ssh-core.js";
import { startSshServer, startHttpProxy, memoryStore, profile, text, wait, USER, PASSWORD } from "./multi-conn-fixture.mjs";

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
const raw = (srv) => ({ host: "127.0.0.1", port: srv.port, username: USER, password: PASSWORD });
const dropped = async (conn) => { for (let i = 0; i < 50 && conn.session?.connected; i++) await wait(20); };

test("a profile named like a raw connection key does not reach the raw connection", async () => {
  const trap = `raw:u@127.0.0.1:${a.port}`;
  const ctx = createCtx({ store: memoryStore([profile(trap, b)]), mode: "stdio" });
  try {
    assert.ok(!(await call(ctx, "ssh_connect", raw(a))).isError);
    const r = await call(ctx, "ssh_execute", { profile: trap, command: "echo:who" });
    assert.ok(!r.isError, text(r));
    assert.match(text(r), /who@B/);
    assert.match(text(await call(ctx, "ssh_execute", { profile: `u@127.0.0.1:${a.port}`, command: "echo:raw" })), /raw@A/);
  } finally {
    destroyCtx(ctx);
  }
});

test("raw connections with IPv6 hosts are found by name", () => {
  const ctx = createCtx({ store: memoryStore([]), mode: "stdio" });
  for (const name of ["u@::1:22", "u@2001:db8::5:2222", "u@fe80::1%eth0:22", "a@b@10.0.0.1:22"]) {
    const conn = { name, key: keysOfName(name)[1], ctx };
    assert.ok(conn.key?.startsWith("raw:"), name);
    ctx.connections.set(conn.key, conn);
    assert.equal(findConn(ctx, name), conn, name);
  }
  assert.equal(keysOfName("U@2001:DB8::5:22")[1], "raw:U@2001:db8::5:22", "the host is case-insensitive, the user is not");
});

test("cleanup_temp removes the temp files of a raw connection", async () => {
  const ctx = createCtx({ store: memoryStore([]), mode: "stdio" });
  try {
    await call(ctx, "ssh_connect", raw(a));
    assert.ok(!(await call(ctx, "ssh_download_file", { remote_path: "/notes.txt" })).isError);
    assert.equal(ctx.tempFiles.size, 1);
    assert.match(text(await call(ctx, "ssh_disconnect", { cleanup_temp: true })), /Temp files removed: 1/);
    assert.equal(ctx.tempFiles.size, 0);
  } finally {
    destroyCtx(ctx);
  }
});

test("ssh_upload refuses the profile store, its siblings and key files", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sshpilot-guard-"));
  try {
    const cfgDir = join(dir, "cfg");
    mkdirSync(cfgDir);
    const path = join(cfgDir, "servers.json");
    writeFileSync(join(cfgDir, "id_test"), "KEY");
    writeFileSync(path, JSON.stringify({ servers: [{ ...profile("alpha", a), privateKeyPath: "id_test" }] }));
    writeFileSync(`${path}.lock`, "");
    const ctx = createCtx({ store: new FileProfileStore(path), mode: "stdio" });
    try {
      await call(ctx, "ssh_connect", raw(a));
      for (const local of [path, `${path}.lock`, join(cfgDir, "id_test"), cfgDir, dir]) {
        const r = await call(ctx, "ssh_upload", { local_path: local, remote_path: "/tmp/x" });
        assert.equal(r.isError, true, local);
        assert.match(text(r), /profile store or a profile's key file/, local);
      }
    } finally {
      destroyCtx(ctx);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a profile's proxy password is not kept, and a reconnect re-resolves the proxy", async () => {
  const px = await startHttpProxy("pu", "pp");
  const store = memoryStore([profile("alpha", a, { proxy: { type: "http", host: "127.0.0.1", port: px.port, username: "pu", password: "pp" } })]);
  const ctx = createCtx({ store, mode: "stdio" });
  try {
    assert.ok(!(await call(ctx, "ssh_connect_profile", { profile_name: "alpha" })).isError);
    const conn = findConn(ctx, "alpha");
    assert.equal(conn.session.proxyUsed.password, undefined);
    assert.equal(conn.lastConnect.proxy.password, undefined);
    assert.equal(conn.session.proxyUsed.username, "pu");
    /* Rotated proxy password: the reconnect takes it from the store. */
    px.password = "pp2";
    store.save({ servers: [{ ...store.cfg.servers[0], proxy: { ...store.cfg.servers[0].proxy, password: "pp2" } }] });
    a.dropClients();
    await dropped(conn);
    const r = await call(ctx, "ssh_execute", { command: "echo:via" });
    assert.ok(!r.isError, text(r));
    assert.match(text(r), /via@A/);
    /* A runtime override changes the route: no silent reconnect around the proxy. */
    ctx.proxyOverride = { mode: "disabled" };
    a.dropClients();
    await dropped(conn);
    const n = a.commands.length;
    const refused = await call(ctx, "ssh_execute", { command: "echo:direct" });
    assert.equal(refused.isError, true);
    assert.match(text(refused), /proxy route .* changed/);
    assert.equal(a.commands.length, n);
  } finally {
    destroyCtx(ctx);
    await px.close();
  }
});

test("an empty profile name still drops credentials; empty names are refused on add and rename", async () => {
  const ctx = createCtx({ store: memoryStore([profile("", a), profile("alpha", a)]), mode: "stdio" });
  try {
    assert.ok(!(await call(ctx, "ssh_connect_profile", { profile_name: "" })).isError);
    const [conn] = [...ctx.connections.values()];
    assert.equal(conn.session.config.password, undefined);
    assert.equal(conn.lastConnect.profile, "");
    assert.equal((await call(ctx, "ssh_server_add", { name: " ", host: "h", username: "u" })).isError, true);
    assert.equal((await call(ctx, "ssh_server_update", { name: "alpha", rename_to: "" })).isError, true);
    assert.ok(ctx.store.cfg.servers.some((s) => s.name === "alpha"));
  } finally {
    destroyCtx(ctx);
  }
});
