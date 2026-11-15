/* stdio keeps the full local tool set; remote and connector sessions get the narrowed ones. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { listToolsFor, isToolAvailable } from "../dist/tools.js";

const LOCAL_ONLY = ["ssh_connect", "ssh_upload", "ssh_temp_path", "ssh_pin_host_keys"];
const PROFILE_ADMIN = ["ssh_server_add", "ssh_server_update", "ssh_server_remove", "ssh_proxy_set", "ssh_proxy_enable", "ssh_proxy_disable"];
const CONNECTION_TOOLS = ["ssh_execute", "ssh_execute_background", "ssh_read_file", "ssh_write_file", "ssh_download_file", "ssh_delete", "ssh_status", "ssh_disconnect"];

test("stdio exposes every local tool, including local-disk, raw connect and key scanning", () => {
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
  assert.deepEqual(remote.filter((n) => !stdio.includes(n)), []);
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

test("connection tools take an optional profile in every mode", () => {
  for (const [mode, scoped] of [["stdio", false], ["remote", false], ["remote", true]]) {
    const defs = new Map(listToolsFor(mode, scoped).map((t) => [t.name, t]));
    for (const n of CONNECTION_TOOLS) {
      const schema = defs.get(n).inputSchema;
      assert.equal(schema.properties.profile?.type, "string", `${mode} ${n}`);
      assert.ok(!(schema.required ?? []).includes("profile"), `${mode} ${n}`);
    }
  }
});

test("remote ssh_connect_profile does not promise trust on first use", () => {
  const def = listToolsFor("remote").find((t) => t.name === "ssh_connect_profile");
  assert.ok(!def.description.includes("trust on first use)"), def.description);
  assert.match(def.description, /--allow-tofu/);
});
