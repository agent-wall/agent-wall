# Getting Started

Get Agent Wall protecting your MCP servers in under 2 minutes.

## Installation

::: code-group

```bash [npm]
npm install -g @agent-wall/cli
```

```bash [pnpm]
pnpm add -g agent-wall
```

```bash [yarn]
yarn global add agent-wall
```

:::

## Quick Start

### 1. Generate a policy config

```bash
agent-wall init
```

This creates `agent-wall.yaml` with sensible defaults.

### 2. Wrap your MCP server

```bash
agent-wall wrap -- npx @modelcontextprotocol/server-filesystem /home/user
```

That's it. Agent Wall is now intercepting every tool call and enforcing your policy.

### 3. Integrate with your MCP client

Update your MCP client config to use Agent Wall as the command:

::: code-group

```json [Claude Code]
// ~/.claude/mcp_servers.json
{
  "mcpServers": {
    "filesystem": {
      "command": "agent-wall",
      "args": ["wrap", "--", "npx", "@modelcontextprotocol/server-filesystem", "/home/user"]
    }
  }
}
```

```json [Cursor]
// ~/.cursor/mcp.json
{
  "mcpServers": {
    "filesystem": {
      "command": "agent-wall",
      "args": ["wrap", "--", "npx", "@modelcontextprotocol/server-filesystem", "/home/user"]
    }
  }
}
```

```json [Claude Desktop]
// ~/Library/Application Support/Claude/claude_desktop_config.json
{
  "mcpServers": {
    "filesystem": {
      "command": "agent-wall",
      "args": ["wrap", "--silent", "--", "npx", "@modelcontextprotocol/server-filesystem", "/home/user"]
    }
  }
}
```

```json [VS Code / Copilot]
// .vscode/mcp.json
{
  "mcpServers": {
    "filesystem": {
      "command": "agent-wall",
      "args": ["wrap", "--", "npx", "@modelcontextprotocol/server-filesystem", "/home/user"]
    }
  }
}
```

```json [Windsurf]
// ~/.codeium/windsurf/mcp_config.json
{
  "mcpServers": {
    "filesystem": {
      "command": "agent-wall",
      "args": ["wrap", "--", "npx", "@modelcontextprotocol/server-filesystem", "/home/user"]
    }
  }
}
```

:::

## Verify It Works

Test a tool call against your policy without starting a server:

```bash
# Should be DENIED (SSH key access)
agent-wall test --tool read_file --arg path=/home/.ssh/id_rsa

# Should be ALLOWED (normal file read)
agent-wall test --tool read_file --arg path=/home/user/project/README.md
```

Run the health check to verify everything is set up:

```bash
agent-wall doctor
```

## Environment Variables

Set these once to avoid repeating flags:

```bash
export AGENT_WALL_CONFIG=/path/to/agent-wall.yaml
export AGENT_WALL_LOG=/var/log/agent-wall.log
```

These are used as fallbacks by `wrap`, `test`, `validate`, and `doctor`.

## What's Next?

- [How It Works](/guide/how-it-works) — Understand the two-way architecture
- [Policy Configuration](/guide/policy-file) — Customize your rules and response scanning
- [Response Scanning](/guide/response-scanning) — Detect leaked secrets in server responses
- [Real-Time Dashboard](/guide/dashboard) — Monitor security events in your browser
- [CLI Reference](/cli/overview) — All available commands
- [Audit Logging](/guide/audit-logging) — Monitor tool call activity
- [Any MCP Client](/guide/any-mcp-client) — Works with every MCP server and client
