/* Encrypted profile vault for remote mode. Profiles are AES-256-GCM encrypted under a random DEK that the file
 * stores only wrapped: once per device token and once under the recovery key, so the file alone decrypts nothing.
 * Revoking a device deletes its wrap, but a revoked device that kept an old copy of this file can still unwrap the
 * DEK it had; `rotate` (recovery key) re-keys the vault, issues a new recovery key and, since other wraps need their
 * tokens, drops every device. */
import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "crypto";
import {
  closeSync,
  existsSync,
  fchownSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import { dirname, join } from "path";
import { homedir, hostname } from "os";
import { expandHome } from "./config.js";
import type { ProfileStore } from "./config.js";
import { plainText } from "./utils.js";
import type { ServerProfile, ServersConfig } from "./types.js";

export type GrantTokenKind = "code" | "access" | "refresh";

export interface DeviceInfo {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt?: string;
}

export interface AuthResult {
  deviceId: string;
  deviceName: string;
  /** Caller owns it and must zero-fill it when done (VaultProfileStore.dispose does). */
  dek: Buffer;
}

interface SealedBox {
  nonce: string;
  ciphertext: string;
  tag: string;
}

interface WrappedDek {
  salt: string;
  wrappedDek: SealedBox;
}

interface DeviceEntry extends WrappedDek {
  id: string;
  name: string;
  tokenHash: string;
  createdAt: string;
  lastUsedAt?: string;
}

interface ClientEntry {
  id: string;
  name: string;
  redirectUris: string[];
  createdAt: string;
}

interface RetryBox {
  salt: string;
  pair: SealedBox;
}

interface TokenEntry {
  kind: GrantTokenKind;
  hash: string;
  expiresAt: string;
  spent?: true;
  salt?: string;
  wrappedKey?: SealedBox;
  redirectUri?: string;
  codeChallenge?: string;
  resource?: string;
  rotatedAt?: string;
  successor?: string;
  retry?: RetryBox;
}

interface GrantEntry {
  id: string;
  label: string;
  clientId: string;
  createdAt: string;
  expiresAt: string;
  createdByDevice: string;
  profileCount: number;
  vault: SealedBox;
  tokens: TokenEntry[];
}

interface VaultFile {
  version: 1;
  vault: SealedBox;
  devices: DeviceEntry[];
  recovery: { salt: string; wrappedDek: SealedBox };
  clients?: ClientEntry[];
  grants?: GrantEntry[];
  clientKey?: string;
}

type ParsedKey = { kind: "device"; id: string; secret: Buffer } | { kind: "recovery"; secret: Buffer };

type Commit = (file: VaultFile) => void;

interface Lock {
  release: () => void;
  commit: Commit;
}

const VAULT_AAD = Buffer.from("mcp-sshpilot-vault-v1", "utf-8");
const RECOVERY_AAD = Buffer.from("recovery", "utf-8");
const KEK_INFO = "mcp-sshpilot-kek-v1";
const KEY_LEN = 32;
const NONCE_LEN = 12;
const TAG_LEN = 16;
const SALT_LEN = 16;
const DEVICE_TOKEN_RE = /^sshp_([0-9a-f]{8})_([A-Za-z0-9_-]{43})$/;
const RECOVERY_KEY_RE = /^sshp_recovery_([A-Za-z0-9_-]{43})$/;
const DEVICE_NAME_RE = /^[\p{L}\p{N} ._@-]{1,64}$/u;
const TOUCH_INTERVAL_MS = 60_000;
const LOCK_WAIT_MS = 5_000;
const LOCK_STALE_MS = 30_000;

/* Write-side caps: a session (or a prompt-injected agent in one) must not grow the vault until every load OOMs. */
const MAX_PROFILES = 1000;
const MAX_PROFILES_BYTES = 4 * 1024 * 1024;
const PROFILE_FIELD_MAX = {
  name: 256,
  host: 255,
  username: 256,
  password: 4096,
  passphrase: 4096,
  privateKey: 32 * 1024,
  hostKeySha256: 128,
  description: 4096,
};

/* Compared against for unknown device ids so a miss costs the same as a wrong secret. */
const DUMMY_HASH = randomBytes(32);

/** MCP_SSHPILOT_VAULT, else ~/.config/mcp-sshpilot/vault.json. Read on every call so tests can switch it. */
export function resolveVaultPath(): string {
  const env = process.env.MCP_SSHPILOT_VAULT;
  if (env && env.trim().length > 0) return expandHome(env.trim());
  return join(homedir(), ".config", "mcp-sshpilot", "vault.json");
}

function seal(key: Buffer, plaintext: Buffer, aad: Buffer): SealedBox {
  const nonce = randomBytes(NONCE_LEN);
  const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_LEN });
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    nonce: nonce.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
  };
}

/* Throws on any tag/AAD/key mismatch. Lengths were checked by validateFile, authTagLength pins the tag size again. */
function unseal(key: Buffer, sealed: SealedBox, aad: Buffer): Buffer {
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(sealed.nonce, "base64"), { authTagLength: TAG_LEN });
  decipher.setAAD(aad);
  decipher.setAuthTag(Buffer.from(sealed.tag, "base64"));
  const head = decipher.update(Buffer.from(sealed.ciphertext, "base64"));
  try {
    const tail = decipher.final();
    const out = Buffer.concat([head, tail]);
    tail.fill(0);
    return out;
  } finally {
    head.fill(0);
  }
}

function deriveKek(secret: Buffer, salt: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", secret, salt, KEK_INFO, KEY_LEN));
}

function wrapDek(dek: Buffer, secret: Buffer, aad: Buffer): WrappedDek {
  const salt = randomBytes(SALT_LEN);
  const kek = deriveKek(secret, salt);
  try {
    return { salt: salt.toString("base64"), wrappedDek: seal(kek, dek, aad) };
  } finally {
    kek.fill(0);
  }
}

/* null on any failure: a wrong key and a tampered wrap must look the same to the caller. */
function unwrapDek(secret: Buffer, salt: string, wrapped: SealedBox, aad: Buffer): Buffer | null {
  const kek = deriveKek(secret, Buffer.from(salt, "base64"));
  try {
    const dek = unseal(kek, wrapped, aad);
    if (dek.length !== KEY_LEN) {
      dek.fill(0);
      return null;
    }
    return dek;
  } catch {
    return null;
  } finally {
    kek.fill(0);
  }
}

function hashSecret(secret: Buffer): Buffer {
  return createHash("sha256").update(secret).digest();
}

function decodeSecret(b64url: string): Buffer | null {
  const secret = Buffer.from(b64url, "base64url");
  /* Reject non-canonical encodings so one secret has exactly one token string. */
  if (secret.length !== KEY_LEN || secret.toString("base64url") !== b64url) {
    secret.fill(0);
    return null;
  }
  return secret;
}

function parseKey(key: string): ParsedKey | null {
  const dev = DEVICE_TOKEN_RE.exec(key);
  if (dev) {
    const secret = decodeSecret(dev[2]);
    return secret ? { kind: "device", id: dev[1], secret } : null;
  }
  const rec = RECOVERY_KEY_RE.exec(key);
  if (rec) {
    const secret = decodeSecret(rec[1]);
    return secret ? { kind: "recovery", secret } : null;
  }
  return null;
}

/** True when the string has the shape of a device token, grant token or recovery key (used to keep them out of argv). */
export function looksLikeVaultKey(s: string): boolean {
  return /sshp_(?:g?[0-9a-f]{8}|recovery)_[A-Za-z0-9_-]{20,}/.test(s);
}

/* ---------- file shape ---------- */

/* No regex: a backtracking one overflows the stack on blobs of a few MB (inside MAX_PROFILES_BYTES). The round trip
 * accepts only canonical base64 (Buffer.from skips invalid characters, so they never survive it). */
function isBase64(v: unknown): v is string {
  return typeof v === "string" && v.length % 4 === 0 && Buffer.from(v, "base64").toString("base64") === v;
}

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/* Errors name the field only, never its value. `writing`: checking what is about to be written, not what was read. */
function validateFile(raw: unknown, path: string, writing = false): VaultFile {
  const bad: (field: string) => never = (field) => {
    throw new Error(
      writing
        ? `Refusing to write the vault: it would not read back (bad ${field}); nothing was written`
        : `Vault file ${path} is corrupted or not an mcp-sshpilot vault (bad ${field})`);
  };
  const b64 = (v: unknown, field: string, len?: number): void => {
    if (!isBase64(v)) bad(field);
    if (len !== undefined && Buffer.from(v, "base64").length !== len) bad(field);
  };
  const sealed = (v: unknown, field: string): void => {
    if (!isObj(v)) bad(field);
    const s = v;
    b64(s.nonce, `${field}.nonce`, NONCE_LEN);
    b64(s.ciphertext, `${field}.ciphertext`);
    b64(s.tag, `${field}.tag`, TAG_LEN);
  };
  const str = (v: unknown, field: string): void => {
    if (typeof v !== "string" || v.length === 0 || v.length > 256) bad(field);
  };
  if (!isObj(raw)) bad("root");
  const f = raw;
  if (f.version !== 1) bad("version");
  sealed(f.vault, "vault");
  if (!isObj(f.recovery)) bad("recovery");
  const rec = f.recovery;
  b64(rec.salt, "recovery.salt", SALT_LEN);
  sealed(rec.wrappedDek, "recovery.wrappedDek");
  if (!Array.isArray(f.devices)) bad("devices");
  const ids = new Set<string>();
  f.devices.forEach((d: unknown, i: number) => {
    const field = `devices[${i}]`;
    if (!isObj(d)) bad(field);
    const e = d;
    if (typeof e.id !== "string" || !/^[0-9a-f]{8}$/.test(e.id) || ids.has(e.id)) bad(`${field}.id`);
    ids.add(e.id);
    str(e.name, `${field}.name`);
    if (typeof e.tokenHash !== "string" || !/^[0-9a-f]{64}$/.test(e.tokenHash)) bad(`${field}.tokenHash`);
    b64(e.salt, `${field}.salt`, SALT_LEN);
    sealed(e.wrappedDek, `${field}.wrappedDek`);
    str(e.createdAt, `${field}.createdAt`);
    if (e.lastUsedAt !== undefined) str(e.lastUsedAt, `${field}.lastUsedAt`);
  });
  const date = (v: unknown, field: string): void => {
    str(v, field);
    if (!Number.isFinite(Date.parse(v as string))) bad(field);
  };
  const uri = (v: unknown, field: string): void => {
    if (typeof v !== "string" || v.length === 0 || v.length > 2048) bad(field);
  };
  if (f.clients !== undefined) {
    if (!Array.isArray(f.clients)) bad("clients");
    const clientIds = new Set<string>();
    f.clients.forEach((c: unknown, i: number) => {
      const field = `clients[${i}]`;
      if (!isObj(c)) bad(field);
      const e = c;
      if (typeof e.id !== "string" || !CLIENT_ID_RE.test(e.id) || clientIds.has(e.id)) bad(`${field}.id`);
      clientIds.add(e.id);
      str(e.name, `${field}.name`);
      if (!Array.isArray(e.redirectUris) || e.redirectUris.length === 0 || e.redirectUris.length > 8) bad(`${field}.redirectUris`);
      e.redirectUris.forEach((u: unknown, j: number) => uri(u, `${field}.redirectUris[${j}]`));
      date(e.createdAt, `${field}.createdAt`);
    });
  }
  if (f.grants !== undefined) {
    if (!Array.isArray(f.grants)) bad("grants");
    const grantIds = new Set<string>();
    f.grants.forEach((g: unknown, i: number) => {
      const field = `grants[${i}]`;
      if (!isObj(g)) bad(field);
      const e = g;
      if (typeof e.id !== "string" || !/^[0-9a-f]{8}$/.test(e.id) || grantIds.has(e.id)) bad(`${field}.id`);
      grantIds.add(e.id);
      str(e.label, `${field}.label`);
      if (typeof e.clientId !== "string" || !CLIENT_ID_RE.test(e.clientId)) bad(`${field}.clientId`);
      date(e.createdAt, `${field}.createdAt`);
      date(e.expiresAt, `${field}.expiresAt`);
      str(e.createdByDevice, `${field}.createdByDevice`);
      if (!Number.isInteger(e.profileCount) || (e.profileCount as number) < 0) bad(`${field}.profileCount`);
      sealed(e.vault, `${field}.vault`);
      if (!Array.isArray(e.tokens)) bad(`${field}.tokens`);
      e.tokens.forEach((t: unknown, j: number) => {
        const tf = `${field}.tokens[${j}]`;
        if (!isObj(t)) bad(tf);
        const k = t;
        if (k.kind !== "code" && k.kind !== "access" && k.kind !== "refresh") bad(`${tf}.kind`);
        if (typeof k.hash !== "string" || !/^[0-9a-f]{64}$/.test(k.hash)) bad(`${tf}.hash`);
        date(k.expiresAt, `${tf}.expiresAt`);
        if (k.spent !== undefined && k.spent !== true) bad(`${tf}.spent`);
        if (k.spent !== true) {
          b64(k.salt, `${tf}.salt`, SALT_LEN);
          sealed(k.wrappedKey, `${tf}.wrappedKey`);
        }
        for (const opt of ["redirectUri", "codeChallenge", "resource"]) if (k[opt] !== undefined) uri(k[opt], `${tf}.${opt}`);
        if (k.rotatedAt !== undefined) date(k.rotatedAt, `${tf}.rotatedAt`);
        if (k.successor !== undefined && (typeof k.successor !== "string" || !/^[0-9a-f]{64}$/.test(k.successor))) bad(`${tf}.successor`);
        if (k.retry !== undefined) {
          if (!isObj(k.retry) || k.kind !== "refresh" || k.spent !== true || k.rotatedAt === undefined || k.successor === undefined) bad(`${tf}.retry`);
          const r = k.retry;
          b64(r.salt, `${tf}.retry.salt`, SALT_LEN);
          sealed(r.pair, `${tf}.retry.pair`);
        }
      });
    });
  }
  if (f.clientKey !== undefined) b64(f.clientKey, "clientKey", KEY_LEN);
  return f as unknown as VaultFile;
}

/* The vault never holds key paths: the remote server must not read keys from its own disk. */
function validateProfiles(cfg: unknown): ServersConfig {
  if (!isObj(cfg) || !Array.isArray(cfg.servers)) throw new Error("Profiles must be an object with a servers array");
  for (const s of cfg.servers) {
    if (!isObj(s) || typeof s.name !== "string" || !s.name || typeof s.host !== "string" || typeof s.username !== "string") {
      throw new Error("Every profile needs string name, host and username");
    }
    if (s.privateKeyPath !== undefined) {
      throw new Error(`Profile "${s.name}": privateKeyPath is not allowed in the vault; store the key inline (privateKey)`);
    }
    if (s.privateKey !== undefined && typeof s.privateKey !== "string") {
      throw new Error(`Profile "${s.name}": privateKey must be a string`);
    }
  }
  return cfg as unknown as ServersConfig;
}

/* Only on writes: a vault written before these limits existed must still open. */
function checkProfileLimits(cfg: ServersConfig): void {
  if (cfg.servers.length > MAX_PROFILES) throw new Error(`Too many profiles (max ${MAX_PROFILES})`);
  for (const s of cfg.servers) {
    for (const [field, max] of Object.entries(PROFILE_FIELD_MAX)) {
      const v = (s as unknown as Record<string, unknown>)[field];
      if (typeof v === "string" && v.length > max) {
        throw new Error(`Profile "${s.name.slice(0, 64)}": ${field} is longer than ${max} characters`);
      }
    }
  }
  if (Buffer.byteLength(JSON.stringify(cfg), "utf-8") > MAX_PROFILES_BYTES) {
    throw new Error(`Profiles exceed ${MAX_PROFILES_BYTES / 1024 / 1024} MiB`);
  }
}

/* ---------- file I/O ---------- */

function statSig(path: string): string | null {
  try {
    /* No field alone tells versions apart: a freed inode number is handed to a later temp file, mtime can be coarse
     * or set back, sizes repeat. All four in exact form (bigint: 64-bit file ids, ns times) make a stale hit need the
     * same inode, size and both timestamps at once. Writers never trust the cache (readFresh under the lock). */
    const st = statSync(path, { bigint: true });
    return `${st.ino}:${st.size}:${st.mtimeNs}:${st.ctimeNs}`;
  } catch {
    return null;
  }
}

function readFresh(path: string): VaultFile {
  let text: string;
  try {
    text = readFileSync(path, "utf-8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(`No vault at ${path}; create one with "mcp-sshpilot vault init"`);
    }
    throw new Error(`Cannot read vault ${path}: ${(e as NodeJS.ErrnoException).code ?? "unknown error"}`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    /* JSON.parse messages quote surrounding text; say nothing about the content. */
    throw new Error(`Vault file ${path} is corrupted or not an mcp-sshpilot vault (not JSON)`);
  }
  return validateFile(raw, path);
}

const readCache = new Map<string, { sig: string; file: VaultFile }>();

/* For read-only paths that run per request (authenticate, deviceExists). Writers always use readFresh under the lock. */
function readCached(path: string): VaultFile {
  const sig = statSig(path);
  const hit = readCache.get(path);
  if (sig && hit && hit.sig === sig) return hit.file;
  const file = readFresh(path);
  if (sig) readCache.set(path, { sig, file });
  else readCache.delete(path);
  return file;
}

function writeFileAtomic(path: string, file: VaultFile): void {
  const dir = dirname(path);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  const target = existsSync(path) ? realpathSync(path) : path;
  /* The replacement is a new 0600 file of whoever runs this; written as another user (sudo, `exec -u root`) the
   * server could no longer read its own vault. root hands it to the old owner, anyone else is refused. */
  const uid = process.getuid?.();
  const owner = uid !== undefined && existsSync(target) ? statSync(target) : null;
  if (owner && uid !== 0 && owner.uid !== uid) {
    throw new Error(`Vault ${path} belongs to uid ${owner.uid}; run vault commands as that user (uid ${uid} would leave the server unable to read it)`);
  }
  const text = JSON.stringify(file, null, 2) + "\n";
  /* What is written must read back: one entry the reader refuses would lock every device out of the vault. */
  validateFile(JSON.parse(text), path, true);
  const tmp = `${target}.${randomBytes(8).toString("hex")}.tmp`;
  try {
    /* fsync before the rename and of the directory after it: the vault is the only copy of every profile and is
     * rewritten often, so a crash right after a rename must not leave it empty where the filesystem does not order it. */
    const fd = openSync(tmp, "wx", 0o600);
    try {
      if (owner && uid === 0 && owner.uid !== 0) fchownSync(fd, owner.uid, owner.gid);
      writeFileSync(fd, text, "utf-8");
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, target);
  } catch (e) {
    try {
      unlinkSync(tmp);
    } catch { /* never created or already renamed */ }
    throw e;
  }
  if (process.platform !== "win32") {
    try {
      const dfd = openSync(dirname(target), "r");
      try {
        fsyncSync(dfd);
      } finally {
        closeSync(dfd);
      }
    } catch { /* directory fsync is not supported everywhere */ }
  }
  readCache.delete(path);
}

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/* Creates lockPath exclusively with owner as its content; false when it already exists. */
function tryCreateLock(lockPath: string, owner: string): boolean {
  let fd: number;
  try {
    fd = openSync(lockPath, "wx", 0o600);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") return false;
    throw e;
  }
  try {
    writeFileSync(fd, owner, "utf-8");
  } catch (e) {
    closeSync(fd);
    try {
      unlinkSync(lockPath);
    } catch { /* best effort */ }
    throw e;
  }
  closeSync(fd);
  return true;
}

/* Content first, then mtime: a file replaced in between pairs the old owner with a fresh mtime, i.e. not stale. */
function readLock(lockPath: string): { owner: string; mtimeMs: number } | null {
  try {
    const owner = readFileSync(lockPath, "utf-8");
    return { owner, mtimeMs: statSync(lockPath).mtimeMs };
  } catch {
    return null;
  }
}

function removeIfOwned(lockPath: string, owner: string): void {
  if (readLock(lockPath)?.owner !== owner) return;
  try {
    unlinkSync(lockPath);
  } catch { /* already gone */ }
}

const LOCK_OWNER_RE = /^(\d+):[^@]*@(.+)$/;

/* Owner "<pid>:<random>@<hostname>". A holder on this host whose process still exists is never stale, however long
 * it takes (a suspended CLI, a blocked --out write): its commit would undo whatever was written after a break.
 * Another host or container cannot be asked, so there only the age counts (and commit re-checks ownership). */
function holderAlive(owner: string): boolean {
  const m = LOCK_OWNER_RE.exec(owner);
  if (!m || m[2] !== hostname()) return false;
  try {
    process.kill(Number(m[1]), 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

/* Breaking a stale lock (its holder crashed) is serialized by a second ".break" lock and re-checks that it is still
 * the same stale lock, so two waiters cannot both break it and the second delete the first one's fresh lock. */
function breakIfStale(lockPath: string): void {
  const seen = readLock(lockPath);
  if (!seen || Date.now() - seen.mtimeMs <= LOCK_STALE_MS || holderAlive(seen.owner)) return;
  const breakPath = `${lockPath}.break`;
  const me = randomBytes(16).toString("hex");
  if (!tryCreateLock(breakPath, me)) {
    /* Left behind only by a breaker that died inside the few lines below; aged out like the lock itself. */
    const b = readLock(breakPath);
    if (b && Date.now() - b.mtimeMs > LOCK_STALE_MS) removeIfOwned(breakPath, b.owner);
    return;
  }
  try {
    const now = readLock(lockPath);
    if (now && now.owner === seen.owner && Date.now() - now.mtimeMs > LOCK_STALE_MS) unlinkSync(lockPath);
  } catch {
    /* released meanwhile */
  } finally {
    removeIfOwned(breakPath, me);
  }
}

function lockBusyError(path: string, lockPath: string): Error {
  let holder = "another process";
  try {
    const m = LOCK_OWNER_RE.exec(readFileSync(lockPath, "utf-8"));
    if (m) holder = `process ${m[1]} on ${m[2] === hostname() ? "this host" : "another host"}`;
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    /* Left by another user (e.g. a crashed root run): it can never be judged stale from here. */
    if (code === "EACCES" || code === "EPERM") holder = `a lock file this user cannot read (${code}); if no vault command is running, remove it`;
  }
  return new Error(`Vault ${path} is locked by ${holder} (${lockPath})`);
}

/* Cross-process lock around read-modify-write: without it a server-side write that read the file before a CLI
 * revoke would write the revoked device back. The lock file names its owner and release removes only its own
 * lock. Returns null when !wait and the lock is busy. */
function acquireLock(path: string, wait: boolean): Lock | null {
  const dir = dirname(path);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  const lockPath = `${existsSync(path) ? realpathSync(path) : path}.lock`;
  const owner = `${process.pid}:${randomBytes(16).toString("hex")}@${hostname()}`;
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    if (tryCreateLock(lockPath, owner)) {
      return {
        release: () => removeIfOwned(lockPath, owner),
        commit: (file) => {
          /* Broken by another container while this holder was stalled: what it read is stale, and writing it would
           * resurrect a device revoked since or drop a pin set since. */
          if (readLock(lockPath)?.owner !== owner) {
            throw new Error("The vault lock was taken over while this command was stalled; nothing was written, run it again");
          }
          dropClosedRetries(file, Date.now());
          writeFileAtomic(path, file);
        },
      };
    }
    breakIfStale(lockPath);
    if (!wait) return null;
    if (Date.now() > deadline) throw lockBusyError(path, lockPath);
    sleepSync(25);
  }
}

function withLock<T>(path: string, fn: (commit: Commit) => T): T {
  const lock = acquireLock(path, true)!;
  try {
    return fn(lock.commit);
  } finally {
    lock.release();
  }
}

function newToken(id: string): { token: string; secret: Buffer } {
  const secret = randomBytes(KEY_LEN);
  return { token: `sshp_${id}_${secret.toString("base64url")}`, secret };
}

/* Device token (hash-checked, then unwrap) or recovery key. Throws one generic message for every failure. */
function unlockDek(file: VaultFile, unlockKey: string): Buffer {
  const fail = () => new Error("Unlock key is not valid for this vault");
  const parsed = parseKey(unlockKey.trim());
  if (!parsed) throw fail();
  try {
    let dek: Buffer | null = null;
    if (parsed.kind === "recovery") {
      dek = unwrapDek(parsed.secret, file.recovery.salt, file.recovery.wrappedDek, RECOVERY_AAD);
    } else {
      const dev = findDeviceConstantTime(file, parsed.id, parsed.secret);
      if (dev) dek = unwrapDek(parsed.secret, dev.salt, dev.wrappedDek, Buffer.from(dev.id, "utf-8"));
    }
    if (!dek) throw fail();
    return dek;
  } finally {
    parsed.secret.fill(0);
  }
}

/* Scans every entry and always runs one timingSafeEqual, so unknown ids and wrong secrets cost the same. */
function findDeviceConstantTime(file: VaultFile, id: string, secret: Buffer): DeviceEntry | null {
  let match: DeviceEntry | undefined;
  for (const d of file.devices) if (d.id === id) match = d;
  const expected = match ? Buffer.from(match.tokenHash, "hex") : DUMMY_HASH;
  const equal = timingSafeEqual(expected, hashSecret(secret));
  return equal && match ? match : null;
}

function encryptProfiles(dek: Buffer, cfg: ServersConfig): SealedBox {
  const plain = Buffer.from(JSON.stringify(cfg), "utf-8");
  try {
    return seal(dek, plain, VAULT_AAD);
  } finally {
    plain.fill(0);
  }
}

function decryptProfiles(dek: Buffer, file: VaultFile): ServersConfig {
  let plain: Buffer;
  try {
    plain = unseal(dek, file.vault, VAULT_AAD);
  } catch {
    throw new Error("Vault cannot be decrypted with this key (it was rotated, or the file was tampered with)");
  }
  try {
    let parsed: unknown;
    try {
      parsed = JSON.parse(plain.toString("utf-8"));
    } catch {
      throw new Error("Vault contents are corrupted");
    }
    return validateProfiles(parsed);
  } finally {
    plain.fill(0);
  }
}

function assertDek(dek: Buffer): void {
  if (!Buffer.isBuffer(dek) || dek.length !== KEY_LEN) throw new Error("Invalid vault key");
}

function checkDeviceName(name: string, file: VaultFile): string {
  const n = name.trim();
  if (!DEVICE_NAME_RE.test(n)) {
    throw new Error("Device name must be 1-64 letters, digits, spaces or . _ @ -");
  }
  /* An id-shaped name would make revoke-device <id|name> ambiguous; a token-shaped one would store a secret in clear. */
  if (/^[0-9a-f]{8}$/i.test(n) || n.toLowerCase().startsWith("sshp_")) {
    throw new Error("Device name must not look like a device id or token");
  }
  if (file.devices.some((d) => d.name.toLowerCase() === n.toLowerCase())) {
    throw new Error(`A device named "${n}" already exists`);
  }
  return n;
}

/**
 * Called with a new secret (recovery key or device token) after everything else succeeded, right before the vault
 * file is replaced. If it throws, the vault stays unchanged: a secret that could not be stored is never committed.
 */
export type BeforeCommit = (secret: string) => void;

/** Creates a new vault holding cfg. Refuses to overwrite an existing file. The recovery key is shown once. */
export function createVault(path: string, cfg: ServersConfig, beforeCommit?: BeforeCommit): { recoveryKey: string } {
  const profiles = validateProfiles(cfg);
  checkProfileLimits(profiles);
  return withLock(path, (commit) => {
    if (existsSync(path)) throw new Error(`A vault already exists at ${path}; refusing to overwrite it`);
    const dek = randomBytes(KEY_LEN);
    const secret = randomBytes(KEY_LEN);
    try {
      const file: VaultFile = {
        version: 1,
        vault: encryptProfiles(dek, profiles),
        devices: [],
        recovery: wrapDek(dek, secret, RECOVERY_AAD),
        clientKey: newClientKey(),
      };
      const recoveryKey = `sshp_recovery_${secret.toString("base64url")}`;
      beforeCommit?.(recoveryKey);
      commit(file);
      return { recoveryKey };
    } finally {
      dek.fill(0);
      secret.fill(0);
    }
  });
}

/** Adds a device; unlockKey is an existing device token or the recovery key. The new token is shown once. */
export function addDevice(path: string, name: string, unlockKey: string, beforeCommit?: BeforeCommit): { id: string; token: string } {
  return withLock(path, (commit) => {
    const file = readFresh(path);
    const deviceName = checkDeviceName(name, file);
    const dek = unlockDek(file, unlockKey);
    let id: string;
    do id = randomBytes(4).toString("hex");
    while (file.devices.some((d) => d.id === id));
    const { token, secret } = newToken(id);
    try {
      const wrap = wrapDek(dek, secret, Buffer.from(id, "utf-8"));
      file.devices.push({
        id,
        name: deviceName,
        tokenHash: hashSecret(secret).toString("hex"),
        salt: wrap.salt,
        wrappedDek: wrap.wrappedDek,
        createdAt: new Date().toISOString(),
      });
      beforeCommit?.(token);
      commit(file);
      return { id, token };
    } finally {
      dek.fill(0);
      secret.fill(0);
    }
  });
}

/** Deletes the device's wrap, so its token stops working at once. Matches id first, then name (case-insensitive). */
export function revokeDevice(path: string, idOrName: string, opts: { keepGrants?: boolean } = {}): boolean {
  return revokeDeviceAndGrants(path, idOrName, opts) !== null;
}

/**
 * revokeDevice that reports what went with it. Connector grants the device approved are removed too unless
 * keepGrants: a stolen device token could have minted one, and it would otherwise outlive the revocation.
 */
export function revokeDeviceAndGrants(
  path: string,
  idOrName: string,
  opts: { keepGrants?: boolean } = {},
): { id: string; name: string; grants: GrantInfo[] } | null {
  return withLock(path, (commit) => {
    const file = readFresh(path);
    const key = idOrName.trim();
    let idx = file.devices.findIndex((d) => d.id === key.toLowerCase());
    if (idx < 0) idx = file.devices.findIndex((d) => d.name.toLowerCase() === key.toLowerCase());
    if (idx < 0) return null;
    const [dev] = file.devices.splice(idx, 1);
    const now = Date.now();
    const gone = opts.keepGrants ? [] : (file.grants ?? []).filter((g) => g.createdByDevice === dev.id);
    const grants = gone.map((g) => grantInfo(file, g, now));
    for (const g of gone) revokeGrantIn(file, g);
    commit(file);
    return { id: dev.id, name: dev.name, grants };
  });
}

export function listDevices(path: string): DeviceInfo[] {
  return readCached(path).devices.map((d) => ({
    id: d.id,
    name: d.name,
    createdAt: d.createdAt,
    ...(d.lastUsedAt ? { lastUsedAt: d.lastUsedAt } : {}),
  }));
}

/** True while the device is still in the vault; cheap enough to call per request (cached by file identity). */
export function deviceExists(path: string, deviceId: string): boolean {
  return readCached(path).devices.some((d) => d.id === deviceId);
}

/**
 * Checks a device token and returns the unwrapped DEK, or null for a malformed, unknown, revoked or wrong token.
 * Recovery keys are not accepted here: they unlock vault administration, not an HTTP session.
 * Throws only when the vault file itself is missing or corrupted.
 */
export function authenticate(path: string, token: string): AuthResult | null {
  if (typeof token !== "string") return null;
  const file = readCached(path);
  const parsed = parseKey(token);
  if (!parsed) return null;
  try {
    if (parsed.kind !== "device") return null;
    const dev = findDeviceConstantTime(file, parsed.id, parsed.secret);
    if (!dev) return null;
    const dek = unwrapDek(parsed.secret, dev.salt, dev.wrappedDek, Buffer.from(dev.id, "utf-8"));
    return dek ? { deviceId: dev.id, deviceName: dev.name, dek } : null;
  } finally {
    parsed.secret.fill(0);
  }
}

/** Records lastUsedAt at most once a minute. Best effort: skipped when another process holds the lock. */
export function touchDevice(path: string, deviceId: string): void {
  const cached = readCached(path).devices.find((d) => d.id === deviceId);
  if (!cached) return;
  if (cached.lastUsedAt && Date.now() - Date.parse(cached.lastUsedAt) < TOUCH_INTERVAL_MS) return;
  const lock = acquireLock(path, false);
  if (!lock) return;
  try {
    const file = readFresh(path);
    const dev = file.devices.find((d) => d.id === deviceId);
    if (!dev) return;
    dev.lastUsedAt = new Date().toISOString();
    lock.commit(file);
  } finally {
    lock.release();
  }
}

export function readProfiles(path: string, dek: Buffer): ServersConfig {
  assertDek(dek);
  return decryptProfiles(dek, readFresh(path));
}

/** Re-encrypts the profiles with a fresh nonce, keeping the device list as it is on disk now. */
export function writeProfiles(path: string, dek: Buffer, cfg: ServersConfig): void {
  assertDek(dek);
  const profiles = validateProfiles(cfg);
  checkProfileLimits(profiles);
  withLock(path, (commit) => {
    const file = readFresh(path);
    /* A session opened before `rotate` still holds the old DEK; writing with it would make the vault unreadable. */
    decryptProfiles(dek, file);
    file.vault = encryptProfiles(dek, profiles);
    commit(file);
  });
}

/**
 * Re-keys the vault with a new DEK and a new recovery key; the old recovery key stops working, so rotating is also
 * how a leaked recovery key is retired. Every device token becomes invalid: the other wraps cannot be rebuilt
 * without their tokens. Add devices again with the new recovery key.
 */
export function rotate(path: string, recoveryKey: string, beforeCommit?: BeforeCommit): { recoveryKey: string } {
  if (!RECOVERY_KEY_RE.test(recoveryKey.trim())) throw new Error("Rotation needs the recovery key");
  return withLock(path, (commit) => {
    const file = readFresh(path);
    const oldDek = unlockDek(file, recoveryKey);
    const newDek = randomBytes(KEY_LEN);
    const secret = randomBytes(KEY_LEN);
    try {
      const profiles = decryptProfiles(oldDek, file);
      /* A new client-id key too: every id issued under the old one stops verifying. */
      const next: VaultFile = {
        version: 1,
        vault: encryptProfiles(newDek, profiles),
        devices: [],
        recovery: wrapDek(newDek, secret, RECOVERY_AAD),
        clientKey: newClientKey(),
      };
      const newKey = `sshp_recovery_${secret.toString("base64url")}`;
      beforeCommit?.(newKey);
      commit(next);
      return { recoveryKey: newKey };
    } finally {
      oldDek.fill(0);
      newDek.fill(0);
      secret.fill(0);
    }
  });
}

/**
 * Read-modify-write of the profiles under one lock, unlocked by a device token or the recovery key. For owner-side
 * administration from the CLI (e.g. pinning a host key out of band). Returns what mutate returns.
 */
export function updateProfiles<T>(path: string, unlockKey: string, mutate: (cfg: ServersConfig) => T): T {
  return withLock(path, (commit) => {
    const file = readFresh(path);
    const dek = unlockDek(file, unlockKey);
    try {
      return mutateProfiles(file, dek, mutate, commit);
    } finally {
      dek.fill(0);
    }
  });
}

/* Decrypts, mutates and commits only when something changed: a no-op leaves the file (and its nonce) alone. */
function mutateProfiles<T>(file: VaultFile, dek: Buffer, mutate: (cfg: ServersConfig) => T, commit: Commit): T {
  const cfg = decryptProfiles(dek, file);
  const before = JSON.stringify(cfg);
  const result = mutate(cfg);
  if (JSON.stringify(cfg) !== before) {
    const profiles = validateProfiles(cfg);
    checkProfileLimits(profiles);
    file.vault = encryptProfiles(dek, profiles);
    commit(file);
  }
  return result;
}

/** ProfileStore over the vault for one remote session. Owns dek and zero-fills it on dispose. */
export class VaultProfileStore implements ProfileStore {
  private readonly path: string;
  private readonly dek: Buffer;
  private closed = false;

  constructor(path: string, dek: Buffer) {
    this.path = path;
    this.dek = dek;
    assertDek(dek);
  }

  private check(): void {
    if (this.closed) throw new Error("Vault store is closed");
  }

  load(): ServersConfig {
    this.check();
    return readProfiles(this.path, this.dek);
  }

  save(cfg: ServersConfig): void {
    this.check();
    writeProfiles(this.path, this.dek, cfg);
  }

  /** One lock around read, mutate and write: an owner's `vault pin-host-key` committed between a separate load and
   * save would be overwritten by this session's older copy. */
  update<T>(mutate: (cfg: ServersConfig) => T): T {
    this.check();
    return withLock(this.path, (commit) => mutateProfiles(readFresh(this.path), this.dek, mutate, commit));
  }

  describe(): string {
    return "encrypted vault";
  }

  resolveKey(profile: ServerProfile): string | undefined {
    if (profile.privateKeyPath) {
      throw new Error(`Profile "${profile.name}": privateKeyPath is not supported in remote mode; store the key inline (privateKey)`);
    }
    return profile.privateKey;
  }

  dispose(): void {
    if (this.closed) return;
    this.closed = true;
    this.dek.fill(0);
  }
}

/* ---------- OAuth clients and connector grants ---------- */

/** A public OAuth client, verified from its self-contained id; nothing is stored for it until a grant is created. */
export interface ClientInfo {
  id: string;
  name: string;
  createdAt: string;
  /** redirectHash() of each registered redirect URI. */
  redirectHashes: string[];
}

export interface GrantInfo {
  id: string;
  label: string;
  clientId: string;
  clientName?: string;
  createdAt: string;
  expiresAt: string;
  createdByDevice: string;
  profileCount: number;
  expired: boolean;
}

export interface GrantAuthResult {
  grantId: string;
  label: string;
  /** Caller owns it and must zero-fill it when done (GrantProfileStore.dispose does). */
  gdek: Buffer;
}

export interface GrantTokens {
  accessToken: string;
  refreshToken: string;
  /** Seconds until the access token expires. */
  expiresIn: number;
}

/**
 * Answer to a code or refresh token request. `recognised`: the token matched an entry of its grant (live or spent),
 * so whoever sent it holds a real secret; such a refusal is no guess and must not reach the failed-auth limiter.
 * `busy` (refreshGrant only): an unknown token that would revoke this grant met a vault lock held by another process;
 * nothing was decided, and the caller asks again later.
 */
export interface GrantTokenResult {
  tokens: GrantTokens | null;
  recognised: boolean;
  busy?: { grantId: string };
}

export interface CreateGrantOptions {
  /** Main vault key of the approving device; only read here, the caller still owns it. */
  dek: Buffer;
  deviceId: string;
  client: ClientInfo;
  label: string;
  lifetimeMs: number;
  /** Exact names of the profiles copied into the grant, each with the profileDigest() the owner was shown. */
  profiles: { name: string; digest: string }[];
  code: { redirectUri: string; codeChallenge: string; resource?: string };
}

interface ClientPayload {
  n: string;
  r: string[];
  t: number;
  x: string;
}

const GRANT_TOKEN_RE = /^sshp_g([0-9a-f]{8})_([A-Za-z0-9_-]{43})$/;
const GRANT_VAULT_AAD = "mcp-sshpilot-grant-v1:";
/* <32 hex HMAC>.<base64url JSON>; a bare 32-hex id is what clients stored before ids became self-contained. */
const CLIENT_ID_RE = /^[0-9a-f]{32}(?:\.[A-Za-z0-9_-]{1,1024})?$/;
const CLIENT_MAX_REDIRECTS = 8;
const CLIENT_NAME_MAX = 64;
/* redirectHash() output, and the nonce registerClient adds (6 random bytes, base64url). */
const REDIRECT_HASH_RE = /^[A-Za-z0-9_-]{16}$/;
const CLIENT_NONCE_RE = /^[A-Za-z0-9_-]{8}$/;
/* How far ahead of this server's clock a client id's issue time may be (clock steps between servers on one vault). */
const CLIENT_CLOCK_SKEW_MS = 60_000;
const MAX_GRANTS = 16;
const MAX_LIVE_TOKENS = 8;
/* Spent codes and rotated refresh tokens remembered per grant. A replay of one revokes the grant; one pushed out of
 * the list is unknown, and an unknown refresh token for a live grant revokes it too. */
const MAX_SPENT_TOKENS = 8;
const CODE_TTL_MS = 60_000;
const ACCESS_TTL_MS = 60 * 60 * 1000;
/* A client that lost the refresh response (or raced itself) presents the rotated token again within this window and
 * gets the same response back. */
const REFRESH_RETRY_MS = 60_000;
const RETRY_KEY_INFO = "mcp-sshpilot-refresh-retry-v1";

export function isGrantToken(s: string): boolean {
  return GRANT_TOKEN_RE.test(s);
}

function parseGrantToken(token: string): { id: string; secret: Buffer } | null {
  if (typeof token !== "string") return null;
  const m = GRANT_TOKEN_RE.exec(token);
  if (!m) return null;
  const secret = decodeSecret(m[2]);
  return secret ? { id: m[1], secret } : null;
}

const iso = (ms: number): string => new Date(ms).toISOString();
const grantVaultAad = (id: string): Buffer => Buffer.from(GRANT_VAULT_AAD + id, "utf-8");
/* Kind in the AAD: a code's or refresh token's wrap can never be opened as an access token's, and vice versa. */
const grantTokenAad = (id: string, kind: GrantTokenKind): Buffer => Buffer.from(`grant:${id}:${kind}`, "utf-8");

function sealGrant(gdek: Buffer, id: string, cfg: ServersConfig): SealedBox {
  const plain = Buffer.from(JSON.stringify(cfg), "utf-8");
  try {
    return seal(gdek, plain, grantVaultAad(id));
  } finally {
    plain.fill(0);
  }
}

function unsealGrant(gdek: Buffer, grant: GrantEntry): ServersConfig {
  let plain: Buffer;
  try {
    plain = unseal(gdek, grant.vault, grantVaultAad(grant.id));
  } catch {
    throw new Error("Connector grant cannot be decrypted with this key");
  }
  try {
    let parsed: unknown;
    try {
      parsed = JSON.parse(plain.toString("utf-8"));
    } catch {
      throw new Error("Connector grant contents are corrupted");
    }
    return validateProfiles(parsed);
  } finally {
    plain.fill(0);
  }
}

/* Every token entry is compared, with one timingSafeEqual each and a dummy one for an unknown grant. */
function findGrantToken(grant: GrantEntry | undefined, secret: Buffer): TokenEntry | null {
  const hash = hashSecret(secret);
  if (!grant) {
    timingSafeEqual(DUMMY_HASH, hash);
    return null;
  }
  let match: TokenEntry | null = null;
  for (const t of grant.tokens) if (timingSafeEqual(Buffer.from(t.hash, "hex"), hash)) match = t;
  return match;
}

const isLive = (t: TokenEntry, now: number): boolean => !t.spent && Date.parse(t.expiresAt) > now;
const retryAad = (id: string): Buffer => Buffer.from(`grant:${id}:refresh-retry`, "utf-8");
const retryKey = (secret: Buffer, salt: Buffer): Buffer => Buffer.from(hkdfSync("sha256", secret, salt, RETRY_KEY_INFO, KEY_LEN));

/* Whether a rotated refresh token's sealed response may still be handed out: 0 <= age < REFRESH_RETRY_MS (a clock
 * stepped back is no retry) and the refresh token issued in its place not rotated yet. Otherwise it leaves the file. */
function retryOpen(grant: GrantEntry, t: TokenEntry, now: number): boolean {
  if (!t.retry || t.rotatedAt === undefined || t.successor === undefined) return false;
  const age = now - Date.parse(t.rotatedAt);
  const next = grant.tokens.find((x) => x.hash === t.successor);
  return age >= 0 && age < REFRESH_RETRY_MS && next?.kind === "refresh" && isLive(next, now);
}

/* On every commit, and through the sweep's pruneExpiredGrants: a sealed response stays no longer than its window. */
function dropClosedRetries(file: VaultFile, now: number): void {
  for (const g of file.grants ?? []) for (const t of g.tokens) if (t.retry && !retryOpen(g, t, now)) delete t.retry;
}

function sealRetry(grantId: string, secret: Buffer, issued: GrantTokens, accessEnd: number): RetryBox {
  const salt = randomBytes(SALT_LEN);
  const key = retryKey(secret, salt);
  const plain = Buffer.from(JSON.stringify({ a: issued.accessToken, r: issued.refreshToken, e: accessEnd }), "utf-8");
  try {
    return { salt: salt.toString("base64"), pair: seal(key, plain, retryAad(grantId)) };
  } finally {
    key.fill(0);
    plain.fill(0);
  }
}

/* The response sealed by sealRetry, with expiresIn counted from now; null when it does not open with this secret. */
function openRetry(grantId: string, secret: Buffer, retry: RetryBox, now: number): GrantTokens | null {
  const key = retryKey(secret, Buffer.from(retry.salt, "base64"));
  let plain: Buffer | null = null;
  try {
    plain = unseal(key, retry.pair, retryAad(grantId));
    const p = JSON.parse(plain.toString("utf-8"));
    if (typeof p.a !== "string" || typeof p.r !== "string" || typeof p.e !== "number") return null;
    return { accessToken: p.a, refreshToken: p.r, expiresIn: Math.max(1, Math.floor((p.e - now) / 1000)) };
  } catch {
    return null;
  } finally {
    key.fill(0);
    plain?.fill(0);
  }
}

/* Drops expired grants and tokens, keeps at most MAX_LIVE_TOKENS live tokens per grant (the oldest non-refresh
 * token goes first, so the connector's refresh token survives) and MAX_SPENT_TOKENS remembered spent ones. A client
 * entry stays only while a grant names it. */
function pruneGrants(file: VaultFile, now: number): void {
  if (file.clients) file.clients = file.clients.filter((c) => (file.grants ?? []).some((g) => g.clientId === c.id && Date.parse(g.expiresAt) > now));
  if (!file.grants) return;
  file.grants = file.grants.filter((g) => Date.parse(g.expiresAt) > now);
  for (const g of file.grants) {
    g.tokens = g.tokens.filter((t) => Date.parse(t.expiresAt) > now);
    for (;;) {
      const live = g.tokens.filter((t) => !t.spent);
      if (live.length <= MAX_LIVE_TOKENS) break;
      const victim = live.find((t) => t.kind !== "refresh") ?? live[0];
      g.tokens.splice(g.tokens.indexOf(victim), 1);
    }
    for (;;) {
      const spent = g.tokens.filter((t) => t.spent);
      if (spent.length <= MAX_SPENT_TOKENS) break;
      g.tokens.splice(g.tokens.indexOf(spent[0]), 1);
    }
  }
}

/* Kept only as a hash until the grant ends (or the spent cap pushes it out): a second use means a leaked token. */
function spend(t: TokenEntry, grant: GrantEntry): void {
  t.spent = true;
  delete t.salt;
  delete t.wrappedKey;
  t.expiresAt = grant.expiresAt;
}

function issueGrantToken(
  grant: GrantEntry,
  gdek: Buffer,
  kind: GrantTokenKind,
  ttlMs: number,
  now: number,
  extra: Partial<TokenEntry> = {},
): { token: string; entry: TokenEntry } {
  const secret = randomBytes(KEY_LEN);
  try {
    const wrap = wrapDek(gdek, secret, grantTokenAad(grant.id, kind));
    const entry: TokenEntry = {
      kind,
      hash: hashSecret(secret).toString("hex"),
      salt: wrap.salt,
      wrappedKey: wrap.wrappedDek,
      expiresAt: iso(Math.min(now + ttlMs, Date.parse(grant.expiresAt))),
      ...extra,
    };
    grant.tokens.push(entry);
    return { token: `sshp_g${grant.id}_${secret.toString("base64url")}`, entry };
  } finally {
    secret.fill(0);
  }
}

function issuePair(grant: GrantEntry, gdek: Buffer, now: number): { tokens: GrantTokens; accessEnd: number; refreshHash: string } {
  const access = issueGrantToken(grant, gdek, "access", ACCESS_TTL_MS, now);
  const refresh = issueGrantToken(grant, gdek, "refresh", Date.parse(grant.expiresAt) - now, now);
  const accessEnd = Date.parse(access.entry.expiresAt);
  const expiresIn = Math.max(1, Math.floor((accessEnd - now) / 1000));
  return { tokens: { accessToken: access.token, refreshToken: refresh.token, expiresIn }, accessEnd, refreshHash: refresh.entry.hash };
}

const refused = (recognised: boolean): GrantTokenResult => ({ tokens: null, recognised });

function revokeGrantIn(file: VaultFile, grant: GrantEntry): void {
  file.grants = (file.grants ?? []).filter((g) => g !== grant);
}

function pkceMatches(challenge: string | undefined, verifier: string): boolean {
  if (!challenge || typeof verifier !== "string" || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return false;
  const computed = Buffer.from(createHash("sha256").update(verifier, "ascii").digest("base64url"), "ascii");
  const expected = Buffer.from(challenge, "ascii");
  return computed.length === expected.length && timingSafeEqual(computed, expected);
}

/** Short digest a client id carries for each redirect URI; the URI itself is still checked against the allowlist. */
export function redirectHash(uri: string): string {
  return createHash("sha256").update(uri, "utf-8").digest("base64url").slice(0, 16);
}

/** An id-shaped label would make revoke-grant <id|label> hit another grant (ids win); a token-shaped one stores a secret. */
export function isGrantLabel(label: string): boolean {
  return label.length > 0 && label.length <= 64 && !/^[0-9a-f]{8}$/i.test(label) && !label.toLowerCase().startsWith("sshp_");
}

/** Digest of one saved profile as the consent page showed it; createGrant refuses a profile that changed since. */
export function profileDigest(profile: ServerProfile): string {
  return createHash("sha256").update(JSON.stringify(profile), "utf-8").digest("hex");
}

const clientMac = (key: Buffer, payload: string): string =>
  createHmac("sha256", key).update(`mcp-sshpilot-client-v1:${payload}`, "utf-8").digest("hex").slice(0, 32);
const newClientKey = (): string => randomBytes(KEY_LEN).toString("base64");

/**
 * Gives a vault written before `vault init` created the client-id key its key. Owner side only (`serve --oauth`
 * start): a registration never writes the vault. True when it wrote one.
 */
export function ensureClientKey(path: string): boolean {
  if (readCached(path).clientKey) return false;
  return withLock(path, (commit) => {
    const file = readFresh(path);
    if (file.clientKey) return false;
    file.clientKey = newClientKey();
    commit(file);
    return true;
  });
}

/* Exactly what registerClient produces, and only that. The key is in every copy of the vault file, and a grant stores
 * its client: a name the file validator refuses would make the whole vault unreadable once a grant carried it. */
function isClientPayload(p: unknown, now: number): p is ClientPayload {
  if (!isObj(p) || Object.keys(p).length !== 4) return false;
  const { n, r, t, x } = p as { n: unknown; r: unknown; t: number; x: unknown };
  return (
    typeof n === "string" && n.length > 0 && n.length <= CLIENT_NAME_MAX && plainText(n, CLIENT_NAME_MAX) === n &&
    Array.isArray(r) && r.length >= 1 && r.length <= CLIENT_MAX_REDIRECTS && new Set(r).size === r.length &&
    r.every((h) => typeof h === "string" && REDIRECT_HASH_RE.test(h)) &&
    Number.isSafeInteger(t) && t >= 0 && t * 1000 <= now + CLIENT_CLOCK_SKEW_MS &&
    typeof x === "string" && CLIENT_NONCE_RE.test(x));
}

/* One encoding per payload, so an id verifies only in the exact form registerClient wrote. */
const encodeClientPayload = (p: ClientPayload): string =>
  Buffer.from(JSON.stringify({ n: p.n, r: p.r, t: p.t, x: p.x }), "utf-8").toString("base64url");

/**
 * Issues a public client (no secret) without storing anything: the id carries name, redirect URI digests and issue
 * time under an HMAC. Read-only, no lock: null while the vault has no client-id key (see ensureClientKey).
 */
export function registerClient(path: string, name: string, redirectUris: string[]): ClientInfo | null {
  const stored = readCached(path).clientKey;
  if (!stored) return null;
  const now = Date.now();
  /* x: two connectors added in the same second still get distinct ids. */
  const p: ClientPayload = { n: name, r: [...new Set(redirectUris.map(redirectHash))], t: Math.floor(now / 1000), x: randomBytes(6).toString("base64url") };
  if (!isClientPayload(p, now)) throw new Error("Client metadata out of range");
  const payload = encodeClientPayload(p);
  const key = Buffer.from(stored, "base64");
  try {
    return { id: `${clientMac(key, payload)}.${payload}`, name, createdAt: iso(p.t * 1000), redirectHashes: p.r };
  } finally {
    key.fill(0);
  }
}

/** Verifies a client id issued by registerClient for this vault; null for anything else. */
export function getClient(path: string, id: string): ClientInfo | null {
  if (typeof id !== "string" || !CLIENT_ID_RE.test(id) || !id.includes(".")) return null;
  const stored = readCached(path).clientKey;
  if (!stored) return null;
  const [mac, payload] = id.split(".");
  const key = Buffer.from(stored, "base64");
  let ok: boolean;
  try {
    ok = timingSafeEqual(Buffer.from(clientMac(key, payload), "ascii"), Buffer.from(mac, "ascii"));
  } finally {
    key.fill(0);
  }
  if (!ok) return null;
  let p: unknown;
  try {
    p = JSON.parse(Buffer.from(payload, "base64url").toString("utf-8"));
  } catch {
    return null;
  }
  if (!isClientPayload(p, Date.now()) || encodeClientPayload(p) !== payload) return null;
  return { id, name: p.n, createdAt: iso(p.t * 1000), redirectHashes: p.r };
}

/**
 * Creates a grant holding a snapshot of the named profiles under a fresh key, and its first authorization code.
 * The main vault key is used only to read the profiles; it is never wrapped for the grant.
 */
export function createGrant(path: string, o: CreateGrantOptions): { grantId: string; code: string } {
  assertDek(o.dek);
  if (!isGrantLabel(o.label)) throw new Error("The grant label must be 1-64 characters and must not look like a grant id or token");
  return withLock(path, (commit) => {
    const file = readFresh(path);
    const now = Date.now();
    pruneGrants(file, now);
    if (!file.devices.some((d) => d.id === o.deviceId)) throw new Error("The device token used for this approval is no longer valid");
    const grants = file.grants ?? (file.grants = []);
    if (grants.length >= MAX_GRANTS) throw new Error(`Too many connector grants (max ${MAX_GRANTS}); revoke one with "vault revoke-grant"`);
    const cfg = decryptProfiles(o.dek, file);
    const wanted = new Map(o.profiles.map((p) => [p.name, p.digest]));
    const servers = cfg.servers.filter((s) => wanted.has(s.name));
    /* Same names are not enough: a profile renamed or re-pointed since the page was shown is not what the owner saw. */
    if (wanted.size === 0 || servers.length !== wanted.size || servers.some((s) => profileDigest(s) !== wanted.get(s.name))) {
      throw new Error("The saved profiles changed meanwhile; start the connection again");
    }
    const clients = file.clients ?? (file.clients = []);
    if (!clients.some((c) => c.id === o.client.id)) {
      /* Kept for list-grants; the redirect URI is the one this grant was approved for. */
      clients.push({ id: o.client.id, name: o.client.name, redirectUris: [o.code.redirectUri], createdAt: o.client.createdAt });
    }
    /* Profiles that inherit the global proxy need it to connect the same way. */
    const snapshot: ServersConfig = { ...(cfg.proxy && servers.some((s) => s.proxy === undefined) ? { proxy: cfg.proxy } : {}), servers };
    let id: string;
    do id = randomBytes(4).toString("hex");
    while (grants.some((g) => g.id === id));
    const gdek = randomBytes(KEY_LEN);
    try {
      const grant: GrantEntry = {
        id,
        label: o.label,
        clientId: o.client.id,
        createdAt: iso(now),
        expiresAt: iso(now + o.lifetimeMs),
        createdByDevice: o.deviceId,
        profileCount: servers.length,
        vault: sealGrant(gdek, id, snapshot),
        tokens: [],
      };
      const { token: code } = issueGrantToken(grant, gdek, "code", CODE_TTL_MS, now, {
        redirectUri: o.code.redirectUri,
        codeChallenge: o.code.codeChallenge,
        ...(o.code.resource ? { resource: o.code.resource } : {}),
      });
      grants.push(grant);
      commit(file);
      return { grantId: id, code };
    } finally {
      gdek.fill(0);
    }
  });
}

/**
 * Authorization code -> access + refresh token; every refusal looks the same to the client. The code is single use:
 * any attempt spends it, and presenting a spent code again revokes the whole grant (the code leaked).
 */
export function redeemCode(
  path: string,
  code: string,
  check: { clientId: string; redirectUri: string; codeVerifier: string; resource?: string },
  onRevoke?: (grantId: string) => void,
): GrantTokenResult {
  const parsed = parseGrantToken(code);
  if (!parsed) return refused(false);
  try {
    /* Lock-free first look at the cached file: a token that matches no entry (spent ones included, so a replay still
     * revokes) never costs the cross-process lock and an uncached parse of the whole vault. */
    const seen = findGrantToken((readCached(path).grants ?? []).find((g) => g.id === parsed.id), parsed.secret);
    if (!seen) return refused(false);
    if (seen.kind !== "code") return refused(true);
    return withLock(path, (commit) => {
      const file = readFresh(path);
      const now = Date.now();
      const grant = (file.grants ?? []).find((g) => g.id === parsed.id);
      const tok = findGrantToken(grant, parsed.secret);
      if (!grant || !tok || tok.kind !== "code") return refused(true);
      if (tok.spent) {
        revokeGrantIn(file, grant);
        commit(file);
        onRevoke?.(grant.id);
        return refused(true);
      }
      if (!isLive(tok, now) || Date.parse(grant.expiresAt) <= now) return refused(true);
      const bound =
        grant.clientId === check.clientId &&
        tok.redirectUri === check.redirectUri &&
        (!tok.resource || !check.resource || tok.resource === check.resource) &&
        pkceMatches(tok.codeChallenge, check.codeVerifier);
      const gdek = bound ? unwrapDek(parsed.secret, tok.salt!, tok.wrappedKey!, grantTokenAad(grant.id, "code")) : null;
      spend(tok, grant);
      try {
        const issued = gdek ? issuePair(grant, gdek, now) : null;
        pruneGrants(file, now);
        commit(file);
        return issued ? { tokens: issued.tokens, recognised: true } : refused(true);
      } finally {
        gdek?.fill(0);
      }
    });
  } finally {
    parsed.secret.fill(0);
  }
}

/* The idempotent retry of a rotation: the rotated token from its own client while retryOpen() holds gets the response
 * that rotation returned, sealed in the file (so a restart in between changes nothing). No new tokens, no write. */
function retryOf(grant: GrantEntry, tok: TokenEntry, secret: Buffer, clientId: string, now: number): GrantTokens | null {
  if (grant.clientId !== clientId || Date.parse(grant.expiresAt) <= now || !retryOpen(grant, tok, now)) return null;
  return openRetry(grant.id, secret, tok.retry!, now);
}

/**
 * Refresh token rotation: a new pair, the old refresh token spent. A retry of the last rotation gets the same pair
 * (retryOf; onRetry is told); any other rotated refresh token, or one whose spent record was pushed out (a thief can
 * rotate MAX_SPENT_TOKENS + 1 times to do that) presented by the grant's own client, is a leak and revokes the grant.
 */
export function refreshGrant(
  path: string,
  refreshToken: string,
  clientId: string,
  onRevoke?: (grantId: string) => void,
  onRetry?: (grantId: string) => void,
): GrantTokenResult {
  const parsed = parseGrantToken(refreshToken);
  if (!parsed) return refused(false);
  try {
    /* Lock-free first look: a token naming no grant, another kind of token, or another client's unknown token never
     * costs the lock. */
    const cached = (readCached(path).grants ?? []).find((g) => g.id === parsed.id);
    const seen = findGrantToken(cached, parsed.secret);
    if (!cached) return refused(false);
    if (seen && seen.kind !== "refresh") return refused(true);
    if (!seen && cached.clientId !== clientId) return refused(false);
    const decide = (commit: Commit): GrantTokenResult => {
      const file = readFresh(path);
      const now = Date.now();
      const grant = (file.grants ?? []).find((g) => g.id === parsed.id);
      const tok = findGrantToken(grant, parsed.secret);
      const recognised = seen !== null || tok !== null;
      if (!grant || (tok && tok.kind !== "refresh")) return refused(recognised);
      if (!tok || tok.spent) {
        if (tok) {
          const again = retryOf(grant, tok, parsed.secret, clientId, now);
          if (again) {
            onRetry?.(grant.id);
            return { tokens: again, recognised: true };
          }
        } else if (grant.clientId !== clientId) {
          /* Checked again on the fresh read: the cached look may predate a change by another process. */
          return refused(recognised);
        }
        revokeGrantIn(file, grant);
        commit(file);
        onRevoke?.(grant.id);
        return refused(recognised);
      }
      if (!isLive(tok, now) || Date.parse(grant.expiresAt) <= now || grant.clientId !== clientId) return refused(true);
      const gdek = unwrapDek(parsed.secret, tok.salt!, tok.wrappedKey!, grantTokenAad(grant.id, "refresh"));
      if (!gdek) return refused(true);
      try {
        spend(tok, grant);
        const issued = issuePair(grant, gdek, now);
        tok.rotatedAt = iso(now);
        tok.successor = issued.refreshHash;
        tok.retry = sealRetry(grant.id, parsed.secret, issued.tokens, issued.accessEnd);
        pruneGrants(file, now);
        commit(file);
        return { tokens: issued.tokens, recognised: true };
      } finally {
        gdek.fill(0);
      }
    };
    if (seen) return withLock(path, decide);
    /* An unknown token needs no secret, only a grant id and its client id: it must never hold the event loop for
     * LOCK_WAIT_MS while another process has the lock. */
    const lock = acquireLock(path, false);
    if (!lock) return { tokens: null, recognised: false, busy: { grantId: parsed.id } };
    try {
      return decide(lock.commit);
    } finally {
      lock.release();
    }
  } finally {
    parsed.secret.fill(0);
  }
}

/** Checks an access token and returns the grant's key, or null for a malformed, unknown, expired or revoked one. */
export function authenticateGrant(path: string, token: string): GrantAuthResult | null {
  const file = readCached(path);
  const parsed = parseGrantToken(token);
  if (!parsed) return null;
  try {
    const now = Date.now();
    const grant = (file.grants ?? []).find((g) => g.id === parsed.id);
    const tok = findGrantToken(grant, parsed.secret);
    if (!grant || !tok || tok.kind !== "access" || !isLive(tok, now) || Date.parse(grant.expiresAt) <= now) return null;
    const gdek = unwrapDek(parsed.secret, tok.salt!, tok.wrappedKey!, grantTokenAad(grant.id, "access"));
    return gdek ? { grantId: grant.id, label: grant.label, gdek } : null;
  } finally {
    parsed.secret.fill(0);
  }
}

function grantInfo(file: VaultFile, g: GrantEntry, now: number): GrantInfo {
  const client = (file.clients ?? []).find((c) => c.id === g.clientId);
  return {
    id: g.id,
    label: g.label,
    clientId: g.clientId,
    ...(client ? { clientName: client.name } : {}),
    createdAt: g.createdAt,
    expiresAt: g.expiresAt,
    createdByDevice: g.createdByDevice,
    profileCount: g.profileCount,
    expired: Date.parse(g.expiresAt) <= now,
  };
}

/** Grant metadata only; needs no key. Profile names and hosts of a grant are encrypted and never listed. */
export function listGrants(path: string): GrantInfo[] {
  const file = readCached(path);
  const now = Date.now();
  return (file.grants ?? []).map((g) => grantInfo(file, g, now));
}

/**
 * Drops expired grants and tokens, and sealed retry responses past their window, from the file now rather than at the
 * next write: they would otherwise still open in a copy of the file taken later. Run by every server's sweep, with
 * or without --oauth. Best effort like touchDevice: skipped while the lock is busy.
 */
export function pruneExpiredGrants(path: string): boolean {
  const now = Date.now();
  const stale = (readCached(path).grants ?? []).some((g) => Date.parse(g.expiresAt) <= now || g.tokens.some((t) => Date.parse(t.expiresAt) <= now || (t.retry !== undefined && !retryOpen(g, t, now))));
  if (!stale) return false;
  const lock = acquireLock(path, false);
  if (!lock) return false;
  try {
    const file = readFresh(path);
    pruneGrants(file, now);
    lock.commit(file);
    return true;
  } finally {
    lock.release();
  }
}

/** Deletes a grant (its key goes with it). Matches id first, then a unique label (case-insensitive). */
export function revokeGrant(path: string, idOrLabel: string): GrantInfo | null {
  return withLock(path, (commit) => {
    const file = readFresh(path);
    const key = idOrLabel.trim();
    const grants = file.grants ?? [];
    let matches = grants.filter((g) => g.id === key.toLowerCase());
    if (matches.length === 0) matches = grants.filter((g) => g.label.toLowerCase() === key.toLowerCase());
    if (matches.length > 1) throw new Error(`${matches.length} grants have this label; revoke by id (see vault list-grants)`);
    const grant = matches[0];
    if (!grant) return null;
    const info = grantInfo(file, grant, Date.now());
    revokeGrantIn(file, grant);
    pruneGrants(file, Date.now());
    commit(file);
    return info;
  });
}

/* A grant session may store exactly one kind of change: a host-key pin on a profile that had none (TOFU). */
function assertPinOnly(before: ServersConfig, after: ServersConfig): void {
  const refuse = (): never => {
    throw new Error("A connector grant cannot change saved profiles; only a first-use host-key pin is stored");
  };
  if (!Array.isArray(after.servers) || after.servers.length !== before.servers.length) refuse();
  if (JSON.stringify(before.proxy ?? null) !== JSON.stringify(after.proxy ?? null)) refuse();
  if (Object.keys(after).some((k) => k !== "servers" && k !== "proxy")) refuse();
  before.servers.forEach((b, i) => {
    const { hostKeySha256: pin, ...rest } = after.servers[i];
    if (b.hostKeySha256 === undefined && typeof pin === "string") {
      if (JSON.stringify(rest) !== JSON.stringify(b)) refuse();
    } else if (JSON.stringify(after.servers[i]) !== JSON.stringify(b)) {
      refuse();
    }
  });
}

/** ProfileStore over one grant's mini-vault for a connector session. Owns gdek and zero-fills it on dispose. */
export class GrantProfileStore implements ProfileStore {
  private readonly path: string;
  private readonly grantId: string;
  private readonly gdek: Buffer;
  private closed = false;

  constructor(path: string, grantId: string, gdek: Buffer) {
    this.path = path;
    this.grantId = grantId;
    this.gdek = gdek;
    assertDek(gdek);
  }

  private grantOf(file: VaultFile): GrantEntry {
    if (this.closed) throw new Error("Vault store is closed");
    const grant = (file.grants ?? []).find((g) => g.id === this.grantId);
    if (!grant || Date.parse(grant.expiresAt) <= Date.now()) throw new Error("This connector grant was revoked or has expired");
    return grant;
  }

  load(): ServersConfig {
    return unsealGrant(this.gdek, this.grantOf(readFresh(this.path)));
  }

  save(cfg: ServersConfig): void {
    this.update((current) => {
      current.servers = cfg.servers;
      if (cfg.proxy === undefined) delete current.proxy;
      else current.proxy = cfg.proxy;
    });
  }

  /** Same lock as every other vault write, so a pin saved here cannot drop a device or grant written meanwhile. */
  update<T>(mutate: (cfg: ServersConfig) => T): T {
    return withLock(this.path, (commit) => {
      const file = readFresh(this.path);
      const grant = this.grantOf(file);
      const cfg = unsealGrant(this.gdek, grant);
      const before: ServersConfig = JSON.parse(JSON.stringify(cfg));
      const result = mutate(cfg);
      if (JSON.stringify(cfg) !== JSON.stringify(before)) {
        assertPinOnly(before, cfg);
        checkProfileLimits(validateProfiles(cfg));
        grant.vault = sealGrant(this.gdek, grant.id, cfg);
        commit(file);
      }
      return result;
    });
  }

  describe(): string {
    return "connector grant (read-only profiles)";
  }

  resolveKey(profile: ServerProfile): string | undefined {
    if (profile.privateKeyPath) throw new Error(`Profile "${profile.name}": privateKeyPath is not supported in remote mode`);
    return profile.privateKey;
  }

  dispose(): void {
    if (this.closed) return;
    this.closed = true;
    this.gdek.fill(0);
  }
}
