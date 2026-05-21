#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({
  name: "mcp-evidence-sdk-compat-server",
  version: "0.1.0",
});

server.registerTool(
  "echo",
  {
    description: "Echo a message for compatibility testing",
    inputSchema: {
      message: z.string(),
    },
  },
  async ({ message }) => {
    return {
      content: [
        {
          type: "text",
          text: `sdk:${message}`,
        },
      ],
    };
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);

