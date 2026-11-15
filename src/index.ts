#!/usr/bin/env node

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createCtx } from "./state.js";
import { FileProfileStore } from "./config.js";
import { createMcpServer } from "./mcp-server.js";
import { runCli } from "./cli.js";

async function runStdio() {
  const store = new FileProfileStore();
  const cfg = store.ensureExists();
  if (cfg.created) {
    console.error(`mcp-sshpilot: created empty servers config at ${cfg.path}`);
  } else {
    console.error(`mcp-sshpilot: using servers config at ${cfg.path}`);
  }
  const server = createMcpServer(createCtx({ store, mode: "stdio" }));
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("mcp-sshpilot started");
}

async function main() {
  const result = await runCli(process.argv.slice(2), { buildServer: createMcpServer });
  if (result === "stdio") {
    await runStdio();
    return;
  }
  /* Not process.exit(): `serve` resolves once listening and the HTTP server keeps the process alive. */
  process.exitCode = result;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
