/* In-process SSH servers on 127.0.0.1 for tests that need a real handshake. Commands: "echo:<text>",
 * "delay:<ms>:<text>", "sh -s" (reads stdin); anything else succeeds silently. Each server records its commands. */
import ssh2 from "ssh2";
import { createHash } from "node:crypto";
import net from "node:net";

const { Server, utils } = ssh2;
const { STATUS_CODE } = utils.sftp;

export const USER = "u";
export const PASSWORD = "p";

export async function startSshServer(tag, files = {}) {
  const hostKey = utils.generateKeyPairSync("ed25519").private;
  const pub = utils.parseKey(hostKey).getPublicSSH();
  const fingerprint = "SHA256:" + createHash("sha256").update(pub).digest("base64").replace(/=+$/, "");
  const state = { tag, fingerprint, commands: [], authAttempts: 0, connections: 0, clients: new Set() };
  const server = new Server({ hostKeys: [hostKey] }, (client) => {
    state.connections++;
    state.clients.add(client);
    client.on("error", () => {});
    client.on("close", () => state.clients.delete(client));
    client.on("authentication", (ctx) => {
      state.authAttempts++;
      if (ctx.method === "password" && ctx.username === USER && ctx.password === PASSWORD) ctx.accept();
      else ctx.reject(["password"]);
    });
    client.on("ready", () => {
      client.on("session", (accept) => {
        const session = accept();
        session.on("exec", (acceptExec, _reject, info) => {
          const stream = acceptExec();
          const cmd = info.command;
          state.commands.push(cmd);
          const done = (out) => {
            if (out !== undefined) stream.write(out);
            stream.exit(0);
            stream.end();
          };
          if (cmd === "sh -s") {
            stream.on("data", () => {});
            stream.on("end", () => done());
            return;
          }
          const delay = /^delay:(\d+):(.*)$/.exec(cmd);
          if (delay) return void setTimeout(() => done(`${delay[2]}@${tag}`), Number(delay[1]));
          const echo = /^echo:(.*)$/.exec(cmd);
          done(echo ? `${echo[1]}@${tag}` : undefined);
        });
        session.on("sftp", (acceptSftp) => {
          const sftp = acceptSftp();
          const open = new Map();
          let next = 0;
          sftp.on("OPEN", (reqid, filename) => {
            if (!(filename in files)) return sftp.status(reqid, STATUS_CODE.NO_SUCH_FILE);
            const h = Buffer.alloc(4);
            h.writeUInt32BE(next, 0);
            open.set(next++, Buffer.from(files[filename]));
            sftp.handle(reqid, h);
          });
          sftp.on("READ", (reqid, handle, offset, length) => {
            const data = open.get(handle.readUInt32BE(0));
            if (!data) return sftp.status(reqid, STATUS_CODE.FAILURE);
            if (offset >= data.length) return sftp.status(reqid, STATUS_CODE.EOF);
            sftp.data(reqid, data.subarray(offset, Math.min(data.length, offset + length)));
          });
          sftp.on("FSTAT", (reqid, handle) => {
            const data = open.get(handle.readUInt32BE(0));
            if (!data) return sftp.status(reqid, STATUS_CODE.FAILURE);
            sftp.attrs(reqid, { mode: 0o100644, uid: 0, gid: 0, size: data.length, atime: 0, mtime: 0 });
          });
          sftp.on("CLOSE", (reqid, handle) => {
            open.delete(handle.readUInt32BE(0));
            sftp.status(reqid, STATUS_CODE.OK);
          });
        });
      });
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  state.port = server.address().port;
  state.close = () =>
    new Promise((resolve) => {
      for (const c of state.clients) c.end();
      server.close(() => resolve());
    });
  /* Drops every live connection from the server side, as an idle cut would. */
  state.dropClients = () => { for (const c of state.clients) c.end(); };
  return state;
}

/** HTTP CONNECT proxy on 127.0.0.1 that wants Basic auth; state.password can be changed (rotated) at any time. */
export async function startHttpProxy(username, password) {
  const state = { password, tunnels: 0, refused: 0, sockets: new Set() };
  const srv = net.createServer((sock) => {
    state.sockets.add(sock);
    sock.on("close", () => state.sockets.delete(sock));
    sock.on("error", () => {});
    let buf = "";
    const onData = (d) => {
      buf += d.toString("latin1");
      const end = buf.indexOf("\r\n\r\n");
      if (end < 0) return;
      sock.removeListener("data", onData);
      const m = /^CONNECT ([^ ]+):(\d+) /.exec(buf);
      const auth = /proxy-authorization: basic (\S+)/i.exec(buf)?.[1];
      const want = Buffer.from(`${username}:${state.password}`).toString("base64");
      if (!m || auth !== want) {
        state.refused++;
        sock.end("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
        return;
      }
      const up = net.connect(Number(m[2]), m[1], () => {
        state.tunnels++;
        sock.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        const rest = buf.slice(end + 4);
        if (rest) up.write(Buffer.from(rest, "latin1"));
        sock.pipe(up).pipe(sock);
      });
      up.on("error", () => sock.destroy());
    };
    sock.on("data", onData);
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  state.port = srv.address().port;
  state.close = () => new Promise((r) => { for (const s of state.sockets) s.destroy(); srv.close(() => r()); });
  return state;
}

/** In-memory ProfileStore; `extra` adds optional methods (resolveKey overrides, ...). */
export function memoryStore(servers, extra = {}) {
  let cfg = { servers };
  return {
    load: () => structuredClone(cfg),
    save: (c) => { cfg = structuredClone(c); },
    describe: () => "memory",
    resolveKey: (p) => p.privateKey,
    get cfg() { return cfg; },
    ...extra,
  };
}

export function profile(name, srv, more = {}) {
  return { name, host: "127.0.0.1", port: srv.port, username: USER, password: PASSWORD, ...more };
}

export const text = (r) => r.content.map((c) => c.text).join("\n");
export const wait = (ms) => new Promise((r) => setTimeout(r, ms));
