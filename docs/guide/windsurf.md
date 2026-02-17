# Windsurf Integration

Protect your Windsurf (Codeium) MCP servers with Agent Wall.

## Setup

### 1. Install Agent Wall

```bash
npm install -g @agent-wall/cli
```

### 2. Generate a policy

```bash
agent-wall init
```

### 3. Update your MCP config

Edit `~/.codeium/windsurf/mcp_config.json`:

**Before:**
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-filesystem", "/home/user"]
    }
  }
}
```

**After:**
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

### 4. Restart Windsurf

Restart your Windsurf editor. Agent Wall is now protecting your MCP server.

## With Audit Logging

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agent-wall",
      "args": ["wrap", "--log-file", "./agent-wall-audit.log", "--", "npx", "@modelcontextprotocol/server-filesystem", "/home/user"]
    }
  }
}
```

## Verify Protection

```bash
agent-wall scan
```
