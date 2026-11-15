/* Builds one MCP Server bound to one SessionCtx; shared by stdio mode (one per process) and remote mode (one per HTTP session). */

import { readFileSync } from "fs";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { listToolsFor } from "./tools.js";
import { handleToolCall } from "./handlers.js";
import { formatLogs } from "./utils.js";
import type { SessionCtx } from "./state.js";

const __pkg = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf-8")
) as { version: string };

export const PACKAGE_VERSION: string = __pkg.version;

export interface ServerHooks {
  /** Runs around every tool call's handler (remote mode: concurrency cap and audit line), so it sees calls the
   * client cancelled too, for as long as they really run. */
  toolCall?<T>(name: string, signal: AbortSignal, run: () => Promise<T>): Promise<T>;
}

/** Every handler closes over the given ctx, never over module state. */
export function createMcpServer(ctx: SessionCtx, hooks: ServerHooks = {}): Server {
  const server = new Server(
    { name: "mcp-sshpilot", version: PACKAGE_VERSION },
    { capabilities: { tools: {}, resources: {} } }
  );

  const tools = listToolsFor(ctx.mode, ctx.scoped);

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));

  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    const run = () => handleToolCall(ctx, request.params.name, request.params.arguments);
    return hooks.toolCall ? hooks.toolCall(request.params.name, extra.signal, run) : run();
  });

  server.setRequestHandler(ListResourcesRequestSchema, async () => ({
    resources: [
      {
        uri: "ssh://logs",
        name: "SSH Session Logs",
        description: "Current SSH session logs",
        mimeType: "text/plain",
      },
    ],
  }));

  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const { uri } = request.params;
    if (uri === "ssh://logs") {
      const logs = ctx.session ? formatLogs(ctx.session.logs) : "No active session";
      return { contents: [{ uri, mimeType: "text/plain", text: logs }] };
    }
    throw new Error(`Unknown resource: ${uri}`);
  });

  return server;
}
