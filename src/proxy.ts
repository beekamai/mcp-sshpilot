import { Socket } from "net";
import { connect as tlsConnect } from "tls";
import { SocksClient } from "socks";
import type { ProxyConfig, ServerProfile, ServersConfig } from "./types.js";
import { getProxyOverride } from "./state.js";

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
  profile: ServerProfile,
  cfg: ServersConfig
): ProxyConfig | undefined {
  const override = getProxyOverride();
  if (override.mode === "disabled") return undefined;
  if (override.mode === "force") return override.proxy;
  if (profile.proxy === null) return undefined;
  if (profile.proxy) return profile.proxy;
  return cfg.proxy;
}

export async function buildProxySocket(
  proxy: ProxyConfig,
  destHost: string,
  destPort: number
): Promise<Socket> {
  if (proxy.type === "socks4" || proxy.type === "socks5") {
    const { socket } = await SocksClient.createConnection({
      proxy: {
        host: proxy.host,
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
  return httpConnectTunnel(proxy, destHost, destPort);
}

function httpConnectTunnel(
  proxy: ProxyConfig,
  destHost: string,
  destPort: number
): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const sock: Socket =
      proxy.type === "https"
        ? (tlsConnect({ host: proxy.host, port: proxy.port, servername: proxy.host }) as unknown as Socket)
        : new Socket();

    const cleanup = () => {
      sock.removeListener("error", onError);
      sock.removeListener("timeout", onTimeout);
    };
    const onError = (e: Error) => {
      cleanup();
      reject(new Error(`HTTP CONNECT proxy error: ${e.message}`));
    };
    const onTimeout = () => {
      cleanup();
      reject(new Error("HTTP CONNECT proxy timeout"));
    };

    sock.setTimeout(30_000);
    sock.once("error", onError);
    sock.once("timeout", onTimeout);

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

    let buf = "";
    const onData = (chunk: Buffer) => {
      buf += chunk.toString("utf8");
      if (buf.includes("\r\n\r\n")) {
        sock.removeListener("data", onData);
        const statusLine = buf.split("\r\n", 1)[0];
        const m = /^HTTP\/1\.[01]\s+(\d{3})/.exec(statusLine);
        if (!m || m[1] !== "200") {
          cleanup();
          sock.destroy();
          reject(new Error(`HTTP CONNECT failed: ${statusLine}`));
          return;
        }
        sock.setTimeout(0);
        cleanup();
        resolve(sock);
      }
    };
    sock.on("data", onData);

    if (proxy.type === "https") {
      sock.once("secureConnect" as any, sendRequest);
    } else {
      sock.connect(proxy.port, proxy.host, sendRequest);
    }
  });
}
