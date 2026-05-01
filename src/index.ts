#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { readFileSync } from "fs";
import { TOOL_DEFINITIONS } from "./tools.js";
import { handleToolCall } from "./handlers.js";
import { state } from "./state.js";
import { formatLogs } from "./utils.js";
import { ensureServersConfigExists } from "./config.js";

const __pkg = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf-8")
) as { version: string };

const server = new Server(
  { name: "mcp-sshpilot", version: __pkg.version },
  { capabilities: { tools: {}, resources: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOL_DEFINITIONS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  return handleToolCall(request.params.name, request.params.arguments);
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
    const logs = state.session ? formatLogs(state.session.logs) : "No active session";
    return { contents: [{ uri, mimeType: "text/plain", text: logs }] };
  }
  throw new Error(`Unknown resource: ${uri}`);
});

async function main() {
  const cfg = ensureServersConfigExists();
  if (cfg.created) {
    console.error(`mcp-sshpilot: created empty servers config at ${cfg.path}`);
  } else {
    console.error(`mcp-sshpilot: using servers config at ${cfg.path}`);
  }
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("mcp-sshpilot started");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
