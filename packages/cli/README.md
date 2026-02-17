# Agent Wall

**Security firewall for AI agents.** Intercepts MCP tool calls, enforces policies, blocks attacks.

> *"Cloudflare for AI agents"* — Zero-config protection for any MCP server.

[![CI](https://github.com/agent-wall/agent-wall/actions/workflows/ci.yml/badge.svg)](https://github.com/agent-wall/agent-wall/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/agent-wall/agent-wall/blob/main/LICENSE)
[![npm](https://img.shields.io/npm/v/agent-wall)](https://www.npmjs.com/package/agent-wall)

## Install

```bash
npm install -g agent-wall
```

## Quick Start

```bash
# Generate a starter policy
agent-wall init

# Wrap any MCP server
agent-wall wrap -- npx @modelcontextprotocol/server-filesystem /home/user

# With real-time dashboard
agent-wall wrap --dashboard -- npx mcp-server
```

## 30-Second Integration

Replace your MCP config entry:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agent-wall",
      "args": ["wrap", "--", "npx", "@modelcontextprotocol/server-filesystem", "/home/user"]
    }
  }
}
```

Works with **Claude Code**, **Cursor**, **Claude Desktop**, **VS Code**, **Windsurf**, and any MCP client.

## Defense-in-Depth Pipeline

Every tool call runs through a **5-step inbound pipeline**:

```
1. Kill Switch     — Emergency deny-all
2. Injection       — 30+ prompt injection patterns
3. Egress Control  — Block SSRF, private IPs, metadata endpoints
4. Policy Engine   — YAML rules (first-match-wins, glob, rate limiting)
5. Chain Detection — Suspicious multi-step patterns
```

Plus an **outbound response scanner** — 14 secret patterns, 5 PII patterns, custom regex.

## CLI Commands

| Command | Description |
|---------|-------------|
| `agent-wall wrap` | Wrap an MCP server with policy enforcement |
| `agent-wall init` | Generate a starter config |
| `agent-wall test` | Dry-run a tool call against your policy |
| `agent-wall audit` | View and analyze audit logs |
| `agent-wall scan` | Scan MCP config for security risks |
| `agent-wall validate` | Validate policy configuration |
| `agent-wall doctor` | Health check for config and environment |

## Documentation

Full docs: [agent-wall.github.io/agent-wall](https://agent-wall.github.io/agent-wall/)

## License

[MIT](https://github.com/agent-wall/agent-wall/blob/main/LICENSE)
