/* Pinning without credentials, and remote mode failing closed on trust-on-first-use. */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createCtx, destroyCtx } from "../dist/state.js";
import { handleToolCall, describeCallTarget } from "../dist/handlers.js";
import { scanHostKey } from "../dist/ssh-core.js";
import { startSshServer, memoryStore, profile, text } from "./multi-conn-fixture.mjs";

let a, b;

before(async () => {
  a = await startSshServer("A");
  b = await startSshServer("B");
});

after(async () => {
  await a?.close();
  await b?.close();
});

const call = (ctx, name, args = {}) => handleToolCall(ctx, name, args);

test("scanHostKey returns the host key and never starts authentication", async () => {
  const auths = a.authAttempts;
  assert.equal(await scanHostKey("127.0.0.1", a.port), a.fingerprint);
  assert.equal(a.authAttempts, auths);
});

test("scanHostKey fails cleanly when nothing listens", async () => {
  await assert.rejects(scanHostKey("127.0.0.1", 1, null, 2_000));
});

test("ssh_pin_host_keys pins unpinned profiles and never overwrites a pin", async () => {
  const wrong = "SHA256:" + "A".repeat(43);
  const store = memoryStore([profile("one", a), profile("two", b), profile("held", a, { hostKeySha256: wrong })]);
  const ctx = createCtx({ store, mode: "stdio" });
  try {
    const auths = a.authAttempts + b.authAttempts;
    const r = text(await call(ctx, "ssh_pin_host_keys"));
    assert.match(r, new RegExp(`one → ${a.fingerprint.replace(/[+/]/g, "\\$&")} \\(pinned\\)`));
    assert.equal(store.cfg.servers[0].hostKeySha256, a.fingerprint);
    assert.equal(store.cfg.servers[1].hostKeySha256, b.fingerprint);
    assert.ok(!r.includes("held"), "pinned profiles are skipped by default");
    const listed = text(await call(ctx, "ssh_pin_host_keys", { profiles: ["held", "ghost"] }));
    assert.match(listed, /held → ⚠️ MISMATCH/);
    assert.match(listed, /ghost → ❌ no such profile/);
    assert.equal(store.cfg.servers[2].hostKeySha256, wrong);
    assert.equal(a.authAttempts + b.authAttempts, auths, "no credentials were offered");
  } finally {
    destroyCtx(ctx);
  }
});

test("remote mode refuses an unpinned profile without allowTofu, before dialing", async () => {
  const ctx = createCtx({ store: memoryStore([profile("fresh", a)]), mode: "remote", allowLocalTargets: true });
  try {
    const seen = a.connections;
    for (const r of [
      await call(ctx, "ssh_connect_profile", { profile_name: "fresh" }),
      await call(ctx, "ssh_execute", { profile: "fresh", command: "echo:x" }),
    ]) {
      assert.equal(r.isError, true);
      assert.match(text(r), /Stop and tell the user/);
      assert.ok(text(r).includes("mcp-sshpilot vault pin-host-key <profile> <SHA256:...>"));
      assert.ok(!text(r).includes("--scan"));
      assert.ok(text(r).includes("--allow-tofu"));
    }
    assert.equal(a.connections, seen, "nothing was dialed");
    assert.equal(ctx.connections.size, 0);
  } finally {
    destroyCtx(ctx);
  }
});

test("remote mode with allowTofu: 'disabled' on a direct profile is allowed, a runtime proxy is not", async () => {
  const store = memoryStore([profile("fresh", a), profile("other", b)]);
  const ctx = createCtx({ store, mode: "remote", allowLocalTargets: true, allowTofu: true });
  try {
    ctx.proxyOverride = { mode: "force", proxy: { type: "socks5", host: "127.0.0.1", port: 1 } };
    const viaProxy = await call(ctx, "ssh_connect_profile", { profile_name: "other" });
    assert.equal(viaProxy.isError, true);
    assert.match(text(viaProxy), /proxy override/);
    ctx.proxyOverride = { mode: "disabled" };
    const direct = await call(ctx, "ssh_connect_profile", { profile_name: "fresh" });
    assert.ok(!direct.isError, text(direct));
    assert.equal(store.cfg.servers[0].hostKeySha256, a.fingerprint);
  } finally {
    destroyCtx(ctx);
  }
});

test("describeCallTarget names the connection a call uses, without secrets", async () => {
  const ctx = createCtx({ store: memoryStore([profile("pinned", a, { hostKeySha256: a.fingerprint })]), mode: "remote", allowLocalTargets: true });
  try {
    assert.equal(describeCallTarget(ctx, {}), "-");
    assert.equal(describeCallTarget(ctx, { profile: "pinned" }), `u@127.0.0.1:${a.port}`);
    await call(ctx, "ssh_connect_profile", { profile_name: "pinned" });
    assert.equal(describeCallTarget(ctx, { command: "id" }), `u@127.0.0.1:${a.port}`);
    assert.equal(describeCallTarget(ctx, { host: "h", username: "root", password: "pw" }), "root@h:22");
    assert.equal(describeCallTarget(ctx, {}, "ssh_list_profiles"), "-");
    assert.equal(describeCallTarget(ctx, null), `u@127.0.0.1:${a.port}`);
  } finally {
    destroyCtx(ctx);
  }
});
