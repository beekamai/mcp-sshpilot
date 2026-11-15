import { Socket } from "net";
import { connect as tlsConnect } from "tls";
import { SocksClient } from "socks";
import type { ProxyConfig, ServerProfile, ServersConfig } from "./types.js";
import type { SessionCtx } from "./state.js";
import { plainText } from "./utils.js";

const CONNECT_TIMEOUT_MS = 30_000;
/* Far above any real CONNECT answer; a proxy streaming without an end of header must not grow memory unbounded. */
const CONNECT_MAX_HEADER_BYTES = 16 * 1024;

export function describeProxy(p?: ProxyConfig | null): string | undefined {
  if (!p) return undefined;
  const auth = p.username ? `${p.username}@` : "";
  return `${p.type}://${auth}${p.host}:${p.port}`;
}

export function validateProxy(p: any): ProxyConfig {
  if (!p || typeof p !== "object") throw new Error("proxy: object expected");
  const type = String(p.type || "").toLowerCase();
  if (!["socks4", "socks5", "http", "https"].includes(type)) {
    throw new Error(`proxy.type must be socks4|socks5|http|https, got: ${p.type}`);
  }
  if (!p.host || typeof p.host !== "string") throw new Error("proxy.host is required");
  const port = Number(p.port);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error("proxy.port must be an integer in 1..65535");
  }
  const out: ProxyConfig = { type: type as ProxyConfig["type"], host: p.host, port };
  if (p.username) out.username = String(p.username);
  if (p.password) out.password = String(p.password);
  return out;
}

export function resolveProxyForProfile(
  ctx: SessionCtx,
  profile: ServerProfile,
  cfg: ServersConfig
): ProxyConfig | undefined {
  const override = ctx.proxyOverride;
  if (override.mode === "disabled") return undefined;
  if (override.mode === "force") return override.proxy;
  if (profile.proxy === null) return undefined;
  if (profile.proxy) return profile.proxy;
  return cfg.proxy;
}

/** connectAddress: where to dial the proxy (an already checked IP); TLS still verifies the proxy by its name. */
export async function buildProxySocket(
  proxy: ProxyConfig,
  destHost: string,
  destPort: number,
  connectAddress: string = proxy.host
): Promise<Socket> {
  if (proxy.type === "socks4" || proxy.type === "socks5") {
    const { socket } = await SocksClient.createConnection({
      proxy: {
        host: connectAddress,
        port: proxy.port,
        type: proxy.type === "socks4" ? 4 : 5,
        userId: proxy.username,
        password: proxy.password,
      },
      command: "connect",
      destination: { host: destHost, port: destPort },
      timeout: 30_000,
    });
    return socket;
  }
  return httpConnectTunnel(proxy, destHost, destPort, connectAddress);
}

function httpConnectTunnel(
  proxy: ProxyConfig,
  destHost: string,
  destPort: number,
  connectAddress: string
): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const sock: Socket =
      proxy.type === "https"
        ? (tlsConnect({ host: connectAddress, port: proxy.port, servername: proxy.host }) as unknown as Socket)
        : new Socket();

    /* Stays for the socket's life: an 'error' with no listener (a proxy resetting after the handshake failed, or before
     * ssh2 attached its own) would end the whole process. ssh2 still gets every error through its own listener. */
    sock.on("error", () => {});
    let done = false;
    const fail = (msg: string) => {
      if (done) return;
      done = true;
      clearTimeout(deadline);
      sock.removeListener("data", onData);
      sock.destroy();
      reject(new Error(msg));
    };
    /* One deadline for the whole handshake: an idle timeout lets a proxy trickle a byte every 29 s forever. */
    const deadline = setTimeout(() => fail("HTTP CONNECT proxy timeout"), CONNECT_TIMEOUT_MS);
    const onError = (e: Error) => fail(`HTTP CONNECT proxy error: ${e.message}`);
    const onClose = () => fail("HTTP CONNECT proxy closed the connection");
    sock.once("error", onError);
    sock.once("close", onClose);

    const sendRequest = () => {
      const auth = proxy.username
        ? `Proxy-Authorization: Basic ${Buffer.from(
            `${proxy.username}:${proxy.password ?? ""}`
          ).toString("base64")}\r\n`
        : "";
      const req =
        `CONNECT ${destHost}:${destPort} HTTP/1.1\r\n` +
        `Host: ${destHost}:${destPort}\r\n` +
        auth +
        `\r\n`;
      sock.write(req);
    };

    let buf = Buffer.alloc(0);
    const onData = (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      const end = buf.indexOf("\r\n\r\n");
      if (end < 0) {
        if (buf.length > CONNECT_MAX_HEADER_BYTES) fail("HTTP CONNECT proxy sent an oversized response header");
        return;
      }
      const lineEnd = buf.indexOf("\r\n");
      const statusLine = plainText(buf.subarray(0, lineEnd).toString("utf8"), 200);
      const m = /^HTTP\/1\.[01]\s+(\d{3})/.exec(statusLine);
      if (!m || m[1] !== "200") {
        fail(`HTTP CONNECT failed: ${statusLine}`);
        return;
      }
      done = true;
      clearTimeout(deadline);
      sock.removeListener("data", onData);
      sock.removeListener("error", onError);
      sock.removeListener("close", onClose);
      /* Bytes past the header already belong to the tunnel (the SSH banner can share the packet). ssh2 pauses,
       * attaches its reader and resumes, so paused + unshifted bytes reach it first. */
      sock.pause();
      if (end + 4 < buf.length) sock.unshift(buf.subarray(end + 4));
      resolve(sock);
    };
    sock.on("data", onData);

    if (proxy.type === "https") {
      sock.once("secureConnect" as any, sendRequest);
    } else {
      sock.connect(proxy.port, connectAddress, sendRequest);
    }
  });
}
