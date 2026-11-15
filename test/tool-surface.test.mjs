/* stdio keeps the full local tool set; remote and connector sessions get the narrowed ones. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { listToolsFor, isToolAvailable } from "../dist/tools.js";

const LOCAL_ONLY = ["ssh_connect", "ssh_upload", "ssh_temp_path"];
const PROFILE_ADMIN = ["ssh_server_add", "ssh_server_update", "ssh_server_remove", "ssh_proxy_set", "ssh_proxy_enable", "ssh_proxy_disable"];

test("stdio exposes every tool, including local-disk and raw connect", () => {
  const names = listToolsFor("stdio").map((t) => t.name);
  for (const n of [...LOCAL_ONLY, ...PROFILE_ADMIN, "ssh_execute_dangerous", "ssh_delete_confirm"]) {
    assert.ok(names.includes(n), n);
  }
  assert.equal(new Set(names).size, names.length, "no duplicate tool names");
});

test("remote drops exactly the local-only tools", () => {
  const stdio = listToolsFor("stdio").map((t) => t.name);
  const remote = listToolsFor("remote").map((t) => t.name);
  assert.deepEqual(stdio.filter((n) => !remote.includes(n)).sort(), [...LOCAL_ONLY].sort());
  for (const n of LOCAL_ONLY) assert.equal(isToolAvailable("remote", n), false, n);
});

test("connector (scoped) sessions cannot change profiles or proxies", () => {
  const scoped = listToolsFor("remote", true).map((t) => t.name);
  for (const n of [...LOCAL_ONLY, ...PROFILE_ADMIN]) {
    assert.ok(!scoped.includes(n), n);
    assert.equal(isToolAvailable("remote", n, true), false, n);
  }
  assert.ok(scoped.includes("ssh_connect_profile"));
});
