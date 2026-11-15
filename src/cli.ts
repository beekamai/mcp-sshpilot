/* Command line: `vault ...` manages the encrypted profile vault, `serve` starts the remote (HTTP) server, no
 * arguments keeps the classic stdio server. Secrets never travel through argv, stderr or logs: unlock keys come
 * from MCP_SSHPILOT_UNLOCK_KEY or stdin, new tokens go to stdout or an --out file. */
import { closeSync, existsSync, fstatSync, fsyncSync, openSync, unlinkSync, writeFileSync, writeSync } from "fs";
import { dirname, resolve } from "path";
import { FileProfileStore, expandHome } from "./config.js";
import { normalizeHostKeyFingerprint } from "./ssh-core.js";
import { checkRedirectUri, normalizePublicUrl } from "./oauth.js";
import { CONTROL_CHARS } from "./utils.js";
import {
  addDevice,
  createVault,
  listDevices,
  listGrants,
  looksLikeVaultKey,
  resolveVaultPath,
  revokeDeviceAndGrants,
  revokeGrant,
  rotate,
  updateProfiles,
} from "./vault.js";
import type { HttpServerOptions } from "./http.js";
import type { ServersConfig } from "./types.js";

export interface CliDeps {
  /** Builds the MCP Server for one remote session (index.ts owns it); required by `serve`. */
  buildServer?: HttpServerOptions["buildServer"];
}

const UNLOCK_ENV = "MCP_SSHPILOT_UNLOCK_KEY";
const MAX_SECRET_LINE = 4096;

const USAGE = `Usage: mcp-sshpilot [command]

  (no command)                         run the stdio MCP server (local mode)
  vault init [--import <servers.json>] [--out <file>]
                                       create the encrypted vault; prints the recovery key once
  vault add-device <name> [--out <file>]
                                       add a device; needs an unlock key; prints its token once
  vault revoke-device <id|name> [--keep-grants]
                                       remove a device; its token stops working at once, and the
                                       connector grants it approved are revoked too (unless --keep-grants)
  vault list-devices                   show devices
  vault list-grants                    show connector (OAuth) grants
  vault revoke-grant <id|label>        remove a connector grant; its tokens and sessions stop at once
  vault rotate [--out <file>]          re-key the vault with the recovery key; prints a NEW recovery key once
                                       and invalidates the old one, ALL device tokens and ALL connector grants
  vault pin-host-key <profile> <SHA256:...> | --clear
                                       pin a profile's SSH host key (verified out of band), or drop the pin
  serve [--host 127.0.0.1] [--port 8722] [--tls-cert <file> --tls-key <file>]
        [--allowed-origin <origin>]... [--trust-proxy] [--insecure-http] [--allow-local-targets]
        [--oauth --public-url <https://host> [--oauth-redirect <uri>]...]
                                       run the remote MCP server (Streamable HTTP); --oauth also lets
                                       Claude connectors in, each limited to the profiles you approve

Vault file: $MCP_SSHPILOT_VAULT, default ~/.config/mcp-sshpilot/vault.json
Unlock key (device token or recovery key): $${UNLOCK_ENV}, otherwise read from stdin. Never pass it as an argument.
`;

class UsageError extends Error {
}

interface ParsedArgs {
  positional: string[];
  values: Map<string, string[]>;
  flags: Set<string>;
}

function parseArgs(args: string[], valueOpts: string[], flagOpts: string[]): ParsedArgs {
  const out: ParsedArgs = { positional: [], values: new Map(), flags: new Set() };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (!a.startsWith("--")) {
      out.positional.push(a);
      continue;
    }
    const eq = a.indexOf("=");
    const name = eq >= 0 ? a.slice(2, eq) : a.slice(2);
    if (flagOpts.includes(name)) {
      if (eq >= 0) throw new UsageError(`--${name} takes no value`);
      out.flags.add(name);
    } else if (valueOpts.includes(name)) {
      const value = eq >= 0 ? a.slice(eq + 1) : args[++i];
      /* `--out --import x` must not create a file named "--import"; a value that starts with -- goes as --name=value. */
      if (value === undefined || value === "" || (eq < 0 && value.startsWith("--"))) throw new UsageError(`--${name} needs a value`);
      out.values.set(name, [...(out.values.get(name) ?? []), value]);
    } else {
      throw new UsageError(`Unknown option --${name}`);
    }
  }
  return out;
}

function single(p: ParsedArgs, name: string): string | undefined {
  const v = p.values.get(name);
  if (v && v.length > 1) throw new UsageError(`--${name} given more than once`);
  return v?.[0];
}

function expectPositional(p: ParsedArgs, count: number, what: string): void {
  if (p.positional.length !== count) throw new UsageError(`Expected ${what}`);
}

function info(msg: string): void {
  process.stderr.write(`mcp-sshpilot: ${msg}\n`);
}

/* Hidden input on a terminal (no echo), first line of piped stdin otherwise. */
function readSecretLine(prompt: string): Promise<string> {
  const stdin = process.stdin;
  if (stdin.isTTY) {
    process.stderr.write(prompt);
    return new Promise<string>((resolvePromise, reject) => {
      let buf = "";
      const done = (err?: Error): void => {
        stdin.removeListener("data", onData);
        stdin.setRawMode(false);
        stdin.pause();
        process.stderr.write("\n");
        if (err) reject(err);
        else resolvePromise(buf);
      };
      const onData = (chunk: Buffer): void => {
        for (const ch of chunk.toString()) {
          if (ch === "\r" || ch === "\n") return done();
          if (ch === "\u0003" || ch === "\u0004") return done(new Error("Aborted"));
          if (ch === "\u007f" || ch === "\b") buf = buf.slice(0, -1);
          else if (ch >= " " && buf.length < MAX_SECRET_LINE) buf += ch;
        }
      };
      stdin.setRawMode(true);
      stdin.resume();
      stdin.on("data", onData);
    });
  }
  return new Promise<string>((resolvePromise, reject) => {
    let buf = "";
    const finish = (err?: Error): void => {
      stdin.removeListener("data", onData);
      stdin.removeListener("end", onEnd);
      stdin.removeListener("error", onError);
      stdin.destroy();
      if (err) reject(err);
      else resolvePromise(buf.split(/\r?\n/, 1)[0]);
    };
    const onData = (chunk: Buffer): void => {
      buf += chunk.toString();
      if (buf.includes("\n")) finish();
      else if (buf.length > MAX_SECRET_LINE) finish(new Error("Unlock key on stdin is too long"));
    };
    const onEnd = (): void => finish();
    const onError = (e: Error): void => finish(e);
    stdin.on("data", onData);
    stdin.on("end", onEnd);
    stdin.on("error", onError);
  });
}

async function readUnlockKey(what: string): Promise<string> {
  const env = process.env[UNLOCK_ENV];
  /* Not inherited by anything this process might spawn later. */
  delete process.env[UNLOCK_ENV];
  const key = (env ?? (await readSecretLine(`${what}: `))).trim();
  if (!key) throw new Error(`No unlock key given (set ${UNLOCK_ENV} or pass it on stdin)`);
  return key;
}

interface SecretSink {
  write(secret: string): void;
  done(): void;
  abort(): void;
}

/* The --out file is created (wx, 0600) before the vault is touched, so an existing file cannot lose a fresh token.
 * The secret is written (and fsynced) before the vault commit: a secret that cannot be stored is never committed. */
function openSecretSink(out: string | undefined, label: string): SecretSink {
  if (!out) {
    let printed = false;
    return {
      write(secret) {
        /* Synchronous, so a closed pipe (EPIPE) throws here instead of losing the secret after the commit. */
        writeSync(process.stdout.fd, secret + "\n");
        /* Redirected to a file (> key.txt): on disk before the commit, like --out. */
        if (fstatSync(process.stdout.fd).isFile()) fsyncSync(process.stdout.fd);
        printed = true;
      },
      done() {
        info(`${label} printed above. It is shown only once; store it now.`);
      },
      abort() {
        if (printed) info(`the ${label.toLowerCase()} printed above is NOT valid: the vault was not changed`);
      },
    };
  }
  const path = resolve(expandHome(out));
  const fd = openSync(path, "wx", 0o600);
  let open = true;
  const close = (): void => {
    if (!open) return;
    open = false;
    closeSync(fd);
  };
  return {
    write(secret) {
      writeFileSync(fd, secret + "\n", "utf-8");
      fsyncSync(fd);
      close();
      /* The new file's directory entry too: after a crash the committed vault must not outlive its only key. */
      if (process.platform !== "win32") {
        try {
          const dfd = openSync(dirname(path), "r");
          try {
            fsyncSync(dfd);
          } finally {
            closeSync(dfd);
          }
        } catch { /* directory fsync is not supported everywhere */ }
      }
    },
    done() {
      info(`${label} written to ${path}`);
    },
    abort() {
      close();
      try {
        unlinkSync(path);
      } catch { /* already gone */ }
    },
  };
}

function inlineKeys(importPath: string): { cfg: ServersConfig; inlined: number } {
  const path = resolve(expandHome(importPath));
  /* FileProfileStore.load() treats a missing file as empty; a typo here must not yield an empty vault. */
  if (!existsSync(path)) throw new Error(`Import file ${path} does not exist`);
  const store = new FileProfileStore(path);
  const cfg = store.load();
  let inlined = 0;
  for (const p of cfg.servers) {
    if (!p.privateKeyPath) continue;
    p.privateKey = store.resolveKey(p);
    delete p.privateKeyPath;
    inlined++;
  }
  return { cfg, inlined };
}

function clean(s: string): string {
  return s.replace(CONTROL_CHARS, "?");
}

function printTable(head: string[], rows: string[][]): void {
  const widths = head.map((h, i) => Math.max(h.length, ...rows.map((r) => r[i].length)));
  for (const r of [head, ...rows]) process.stdout.write(r.map((c, i) => c.padEnd(widths[i])).join("  ").trimEnd() + "\n");
}

async function runVault(args: string[]): Promise<number> {
  const [sub, ...rest] = args;
  const vaultPath = resolveVaultPath();
  switch (sub) {
    case "init": {
      const p = parseArgs(rest, ["import", "out"], []);
      expectPositional(p, 0, "no positional arguments for vault init");
      const importPath = single(p, "import");
      const { cfg, inlined } = importPath ? inlineKeys(importPath) : { cfg: { servers: [] } as ServersConfig, inlined: 0 };
      const sink = openSecretSink(single(p, "out"), "Recovery key");
      try {
        createVault(vaultPath, cfg, (key) => sink.write(key));
      } catch (e) {
        sink.abort();
        throw e;
      }
      info(`vault created at ${vaultPath} with ${cfg.servers.length} profile(s)${importPath ? `, ${inlined} key file(s) inlined` : ""}`);
      if (importPath) info(`${importPath} was not modified; delete it if it should not stay on disk in plaintext.`);
      sink.done();
      info(`keep the recovery key offline; add a device with: mcp-sshpilot vault add-device <name>`);
      return 0;
    }
    case "add-device": {
      const p = parseArgs(rest, ["out"], []);
      expectPositional(p, 1, "a device name: vault add-device <name>");
      const unlockKey = await readUnlockKey("Unlock key (device token or recovery key)");
      const sink = openSecretSink(single(p, "out"), "Device token");
      let added: { id: string; token: string };
      try {
        added = addDevice(vaultPath, p.positional[0], unlockKey, (token) => sink.write(token));
      } catch (e) {
        sink.abort();
        throw e;
      }
      info(`device "${clean(p.positional[0].trim())}" added (id ${added.id})`);
      sink.done();
      return 0;
    }
    case "revoke-device": {
      const p = parseArgs(rest, [], ["keep-grants"]);
      expectPositional(p, 1, "a device id or name: vault revoke-device <id|name> [--keep-grants]");
      const revoked = revokeDeviceAndGrants(vaultPath, p.positional[0], { keepGrants: p.flags.has("keep-grants") });
      if (!revoked) {
        info(`no device with id or name "${clean(p.positional[0])}"`);
        return 1;
      }
      info(`device "${clean(revoked.name)}" (${revoked.id}) revoked; its token no longer works. Run "vault rotate" if it may have copied the vault file.`);
      for (const g of revoked.grants) info(`connector grant ${g.id} ("${clean(g.label)}") it approved was revoked too.`);
      if (p.flags.has("keep-grants")) info(`connector grants it approved were kept; see "vault list-grants" (DEVICE column).`);
      return 0;
    }
    case "list-devices": {
      const p = parseArgs(rest, [], []);
      expectPositional(p, 0, "no arguments for vault list-devices");
      const devices = listDevices(vaultPath);
      if (devices.length === 0) {
        info(`no devices in ${vaultPath}`);
        return 0;
      }
      const rows = devices.map((d) => [d.id, clean(d.name), d.createdAt, d.lastUsedAt ?? "never"]);
      printTable(["ID", "NAME", "CREATED", "LAST USED"], rows);
      return 0;
    }
    case "list-grants": {
      const p = parseArgs(rest, [], []);
      expectPositional(p, 0, "no arguments for vault list-grants");
      const grants = listGrants(vaultPath);
      if (grants.length === 0) {
        info(`no connector grants in ${vaultPath}`);
        return 0;
      }
      const devices = new Map(listDevices(vaultPath).map((d) => [d.id, d.name]));
      const rows = grants.map((g) => [
        g.id,
        clean(g.label),
        clean(g.clientName ?? g.clientId.slice(0, 8)),
        /* The approving device, flagged when it was revoked with --keep-grants. */
        devices.has(g.createdByDevice) ? `${g.createdByDevice} (${clean(devices.get(g.createdByDevice)!)})` : `${clean(g.createdByDevice)} (revoked)`,
        g.createdAt,
        g.expired ? `${g.expiresAt} (expired)` : g.expiresAt,
        String(g.profileCount),
      ]);
      printTable(["ID", "LABEL", "CLIENT", "DEVICE", "CREATED", "EXPIRES", "PROFILES"], rows);
      return 0;
    }
    case "revoke-grant": {
      const p = parseArgs(rest, [], []);
      expectPositional(p, 1, "a grant id or label: vault revoke-grant <id|label>");
      const revoked = revokeGrant(vaultPath, p.positional[0]);
      if (!revoked) {
        info(`no grant with id or label "${clean(p.positional[0])}"`);
        return 1;
      }
      info(`grant ${revoked.id} ("${clean(revoked.label)}") revoked; its tokens no longer work and a running server ends its sessions on the next request.`);
      return 0;
    }
    case "rotate": {
      const p = parseArgs(rest, ["out"], []);
      expectPositional(p, 0, "no positional arguments for vault rotate");
      const recoveryKey = await readUnlockKey("Recovery key");
      const sink = openSecretSink(single(p, "out"), "New recovery key");
      try {
        rotate(vaultPath, recoveryKey, (key) => sink.write(key));
      } catch (e) {
        sink.abort();
        throw e;
      }
      info("vault re-keyed. The old recovery key, every device token and every connector grant are now invalid; add devices again with the new recovery key.");
      sink.done();
      return 0;
    }
    case "pin-host-key": {
      const p = parseArgs(rest, [], ["clear"]);
      const clear = p.flags.has("clear");
      expectPositional(p, clear ? 1 : 2, "vault pin-host-key <profile> <SHA256:...>, or vault pin-host-key <profile> --clear");
      const [name, given] = p.positional;
      const pin = clear ? undefined : normalizeHostKeyFingerprint(given);
      if (pin !== undefined && !/^SHA256:[A-Za-z0-9+/]{43}$/.test(pin)) {
        throw new UsageError("Fingerprint must look like SHA256:<43 base64 characters>, as ssh-keygen -lf prints it");
      }
      const unlockKey = await readUnlockKey("Unlock key (device token or recovery key)");
      const profileName = updateProfiles(vaultPath, unlockKey, (cfg) => {
        const profile = cfg.servers.find((s) => s.name.toLowerCase() === name.toLowerCase());
        if (!profile) throw new Error(`No profile named "${clean(name)}"`);
        if (pin) profile.hostKeySha256 = pin;
        else delete profile.hostKeySha256;
        return profile.name;
      });
      info(pin
        ? `profile "${clean(profileName)}" pinned to ${pin}`
        : `host key pin of "${clean(profileName)}" dropped; its next direct connection pins whatever key the server presents`);
      return 0;
    }
    default:
      throw new UsageError(sub ? `Unknown vault command "${clean(sub)}"` : "Missing vault command");
  }
}

function parseServe(args: string[]): Omit<HttpServerOptions, "buildServer"> {
  const p = parseArgs(
    args,
    ["host", "port", "tls-cert", "tls-key", "allowed-origin", "public-url", "oauth-redirect"],
    ["insecure-http", "trust-proxy", "allow-local-targets", "oauth"],
  );
  expectPositional(p, 0, "no positional arguments for serve");
  const portText = single(p, "port") ?? "8722";
  if (!/^\d{1,5}$/.test(portText) || Number(portText) > 65535) throw new UsageError(`Invalid --port ${clean(portText)}`);
  const tlsCert = single(p, "tls-cert");
  const tlsKey = single(p, "tls-key");
  if (!tlsCert !== !tlsKey) throw new UsageError("--tls-cert and --tls-key go together");
  const allowedOrigins = (p.values.get("allowed-origin") ?? []).map((o) => {
    let origin: string | undefined;
    try {
      origin = new URL(o).origin;
    } catch { /* reported below */ }
    /* Exact origins only (scheme://host[:port]); the Origin header is compared verbatim. */
    if (!origin || origin === "null" || origin !== o) {
      throw new UsageError(`Invalid --allowed-origin ${clean(o)} (expected scheme://host[:port], no path or trailing slash)`);
    }
    return origin;
  });
  const publicUrl = single(p, "public-url");
  const oauthRedirects = p.values.get("oauth-redirect") ?? [];
  const oauthOn = p.flags.has("oauth");
  if (!oauthOn && (publicUrl || oauthRedirects.length > 0)) throw new UsageError("--public-url and --oauth-redirect need --oauth");
  if (oauthOn && !publicUrl) throw new UsageError("--oauth needs --public-url (the https origin clients reach this server at)");
  let oauth: HttpServerOptions["oauth"];
  if (oauthOn) {
    try {
      oauth = { publicUrl: normalizePublicUrl(publicUrl!), redirectUris: oauthRedirects.map(checkRedirectUri) };
    } catch (e) {
      throw new UsageError((e as Error).message);
    }
  }
  return {
    host: single(p, "host") ?? "127.0.0.1",
    port: Number(portText),
    ...(tlsCert ? { tlsCert: resolve(expandHome(tlsCert)), tlsKey: resolve(expandHome(tlsKey!)) } : {}),
    allowedOrigins,
    insecureHttp: p.flags.has("insecure-http"),
    trustProxy: p.flags.has("trust-proxy"),
    allowLocalTargets: p.flags.has("allow-local-targets"),
    ...(oauth ? { oauth } : {}),
    vaultPath: resolveVaultPath(),
  };
}

async function runServe(args: string[], deps: CliDeps): Promise<number> {
  const opts = parseServe(args);
  /* Fail before listening when the vault is missing or corrupted (listDevices validates the whole file). */
  if (listDevices(opts.vaultPath).length === 0) {
    info(`warning: vault ${opts.vaultPath} has no devices, every request will be rejected. Add one with "vault add-device".`);
  }
  if (!deps.buildServer) throw new Error("serve is not available: runCli was called without buildServer");
  /* Loaded lazily so vault commands and stdio mode never pull in the HTTP stack. */
  const { startHttpServer } = await import("./http.js");
  await startHttpServer({ ...opts, buildServer: deps.buildServer });
  return 0;
}

/**
 * Entry point for the binary; argv excludes the node executable and script (process.argv.slice(2)).
 * Returns "stdio" when no command is given, otherwise an exit code. `serve` resolves with 0 once listening and the
 * server keeps the process alive, so the caller must set process.exitCode rather than call process.exit().
 */
export async function runCli(argv: string[], deps: CliDeps = {}): Promise<number | "stdio"> {
  if (argv.length === 0) return "stdio";
  try {
    if (argv.some(looksLikeVaultKey)) {
      throw new UsageError(`Tokens and recovery keys are not accepted as arguments (they leak via shell history and ps); use ${UNLOCK_ENV} or stdin`);
    }
    const [cmd, ...rest] = argv;
    switch (cmd) {
      case "vault":
        return await runVault(rest);
      case "serve":
        return await runServe(rest, deps);
      case "help":
      case "--help":
      case "-h":
        process.stdout.write(USAGE);
        return 0;
      default:
        throw new UsageError(`Unknown command "${clean(cmd)}"`);
    }
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`mcp-sshpilot: ${e.message}\n\n${USAGE}`);
      return 2;
    }
    info(e instanceof Error ? e.message : String(e));
    return 1;
  }
}
