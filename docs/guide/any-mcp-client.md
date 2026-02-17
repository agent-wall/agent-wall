# Any MCP Client or Server

Agent Wall works with **every MCP server and every MCP client** that uses stdio transport. No code changes needed.

## Why it works universally

Agent Wall operates at the **protocol level**. The MCP protocol uses [JSON-RPC 2.0](https://www.jsonrpc.org/specification) over stdio with newline-delimited messages. Agent Wall:

1. Spawns your MCP server as a child process
2. Intercepts the stdin/stdout byte stream
3. Parses JSON-RPC messages
4. Evaluates `tools/call` requests against your policy
5. Passes everything else through untouched

It doesn't know or care what the server does — it only sees the protocol messages. So whether you're running a filesystem server, a Stripe server, a custom Python server, or any of the 1000+ MCP servers available, Agent Wall protects it the same way.

## Any MCP server

```bash
# Official MCP servers
agent-wall wrap -- npx @modelcontextprotocol/server-filesystem /path
agent-wall wrap -- npx @modelcontextprotocol/server-github
agent-wall wrap -- npx @modelcontextprotocol/server-playwright
agent-wall wrap -- npx @modelcontextprotocol/server-slack

# Popular third-party servers
agent-wall wrap -- npx @supabase/mcp-server-supabase
agent-wall wrap -- npx @stripe/mcp-server-stripe
agent-wall wrap -- npx mcp-server-postgres postgresql://localhost/db

# Servers written in any language
agent-wall wrap -- node my-server.js
agent-wall wrap -- python my_server.py
agent-wall wrap -- go run ./cmd/mcp-server
agent-wall wrap -- cargo run --bin my-mcp-server

# Docker-based servers
agent-wall wrap -- docker run -i my-mcp-server
```

## Any MCP client

The integration pattern is always the same: replace the server command with `agent-wall wrap -- <original-command>`.

### Supported clients (with auto-detection)

These clients are auto-detected by `agent-wall scan` and `agent-wall doctor`:

| Client | Config Location |
|--------|----------------|
| Claude Code | `~/.claude/mcp_servers.json` |
| Claude Desktop | Platform-specific (see [Claude Desktop guide](/guide/claude-desktop)) |
| Cursor | `~/.cursor/mcp.json` |
| VS Code / Copilot | `.vscode/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Cline | `~/.cline/mcp_settings.json` |
| Continue.dev | `~/.continue/config.json` |

### Other MCP clients

For any MCP client not listed above, the integration is the same. Find where the client stores its MCP server config and change the command:

**Before:**
```json
{
  "command": "npx",
  "args": ["some-mcp-server", "--flag"]
}
```

**After:**
```json
{
  "command": "agent-wall",
  "args": ["wrap", "--", "npx", "some-mcp-server", "--flag"]
}
```

You can also scan a custom config file:

```bash
agent-wall scan --config /path/to/your/mcp-config.json
```

## FAQ

### Do I need to update Agent Wall when new MCP servers are released?

**No.** Agent Wall works at the protocol level. New MCP servers use the same JSON-RPC 2.0 protocol, so they're automatically supported.

The `scan` command has risk detection patterns for 48 known server types (for reporting purposes), but the `wrap` command and policy engine work with any server regardless.

### Does it work with remote MCP servers (SSE/HTTP)?

Currently, Agent Wall supports **stdio transport** only (which is what most MCP clients use). Remote server support (SSE/HTTP) is planned for a future release.

### Does it work with servers that use environment variables?

Yes. When you wrap a server, the child process inherits the parent's environment. You can also set env vars in your MCP client config:

```json
{
  "command": "agent-wall",
  "args": ["wrap", "--", "npx", "mcp-server-postgres"],
  "env": {
    "DATABASE_URL": "postgresql://localhost/mydb"
  }
}
```
