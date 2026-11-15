/* stdio mode: several processes share one servers.json and one temp directory. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, readFileSync, statSync, symlinkSync, existsSync, writeFileSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { FileProfileStore, updateStore } from "../dist/config.js";
import { createCtx } from "../dist/state.js";
import { saveTempFile } from "../dist/temp.js";
import { runCli } from "../dist/cli.js";

const configUrl = pathToFileURL(join(import.meta.dirname, "..", "dist", "config.js")).href;

function writer(path, tag, n) {
  const code = `
    const { FileProfileStore, updateStore } = await import(${JSON.stringify(configUrl)});
    const store = new FileProfileStore(${JSON.stringify(path)});
    for (let i = 0; i < ${n}; i++) {
      updateStore(store, (cfg) => { cfg.servers.push({ name: "${tag}-" + i, host: "192.0.2.1", username: "u" }); });
    }`;
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, ["--input-type=module", "-e", code], { stdio: ["ignore", "ignore", "pipe"] });
    let err = "";
    p.stderr.on("data", (d) => (err += d));
    p.on("exit", (c) => (c === 0 ? resolve() : reject(new Error(err))));
  });
}

function reader(path, n) {
  const code = `
    const { FileProfileStore } = await import(${JSON.stringify(configUrl)});
    const store = new FileProfileStore(${JSON.stringify(path)});
    for (let i = 0; i < ${n}; i++) store.load();`;
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, ["--input-type=module", "-e", code], { stdio: ["ignore", "ignore", "pipe"] });
    let err = "";
    p.stderr.on("data", (d) => (err += d));
    p.on("exit", (c) => (c === 0 ? resolve() : reject(new Error(err))));
  });
}

test("parallel writers and readers from separate processes lose no profile", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sshpilot-store-"));
  try {
    const path = join(dir, "servers.json");
    new FileProfileStore(path).ensureExists();
    await Promise.all([writer(path, "a", 40), writer(path, "b", 40), writer(path, "c", 40), reader(path, 3000), reader(path, 3000)]);
    const names = JSON.parse(readFileSync(path, "utf8")).servers.map((s) => s.name);
    assert.equal(names.length, 120);
    assert.equal(new Set(names).size, 120);
    assert.ok(!existsSync(`${path}.lock`), "lock file is released");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("update writes nothing when mutate changes nothing", () => {
  const dir = mkdtempSync(join(tmpdir(), "sshpilot-store-"));
  try {
    const path = join(dir, "servers.json");
    const store = new FileProfileStore(path);
    store.ensureExists();
    const before = statSync(path).mtimeMs;
    assert.equal(updateStore(store, () => 42), 42);
    assert.equal(statSync(path).mtimeMs, before);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a value option does not swallow the next option", async () => {
  const errs = [];
  const orig = process.stderr.write;
  process.stderr.write = (chunk) => (errs.push(String(chunk)), true);
  try {
    const code = await runCli(["serve", "--host", "--port", "0"], { buildServer: () => { throw new Error("must not start"); } });
    assert.equal(code, 2);
    assert.ok(errs.join("").includes("--host needs a value"), errs.join(""));
  } finally {
    process.stderr.write = orig;
  }
});

const posix = typeof process.getuid === "function";

test("shared temp dir is tightened to 0700", { skip: !posix && "POSIX only" }, () => {
  const base = mkdtempSync(join(tmpdir(), "sshpilot-tmp-"));
  try {
    const dir = join(base, "files");
    mkdirSync(dir, { mode: 0o777 });
    const ctx = createCtx({ store: new FileProfileStore(join(base, "servers.json")), mode: "stdio", tempDir: dir });
    saveTempFile(ctx, "/etc/hostname", Buffer.from("x"), "h");
    assert.equal(statSync(dir).mode & 0o777, 0o700);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("shared temp dir that is a symlink is not used", { skip: !posix && "POSIX only" }, () => {
  const base = mkdtempSync(join(tmpdir(), "sshpilot-tmp-"));
  try {
    const real = join(base, "real");
    mkdirSync(real, { mode: 0o700 });
    const link = join(base, "link");
    symlinkSync(real, link);
    const ctx = createCtx({ store: new FileProfileStore(join(base, "servers.json")), mode: "stdio", tempDir: link });
    const tf = saveTempFile(ctx, "/etc/hostname", Buffer.from("x"), "h");
    assert.ok(!tf.localPath.startsWith(link), "falls back to a private directory");
    assert.equal(ctx.ownsTempDir, true);
    rmSync(ctx.tempDir, { recursive: true, force: true });
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("a stale servers.json lock left by a dead session is broken by age", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sshpilot-store-"));
  try {
    const path = join(dir, "servers.json");
    const store = new FileProfileStore(path);
    store.ensureExists();
    writeFileSync(`${path}.lock`, "");
    const old = new Date(Date.now() - 60_000);
    utimesSync(`${path}.lock`, old, old);
    updateStore(store, (cfg) => { cfg.servers.push({ name: "x", host: "192.0.2.1", username: "u" }); });
    assert.equal(store.load().servers.length, 1);
    assert.ok(!existsSync(`${path}.lock`));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a fresh servers.json lock makes a writer wait, then fail with a clear message", () => {
  const dir = mkdtempSync(join(tmpdir(), "sshpilot-store-"));
  try {
    const path = join(dir, "servers.json");
    const store = new FileProfileStore(path);
    store.ensureExists();
    writeFileSync(`${path}.lock`, "");
    assert.throws(() => updateStore(store, (cfg) => { cfg.servers.push({ name: "x", host: "h", username: "u" }); }), /locked by another session/);
    assert.equal(store.load().servers.length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
