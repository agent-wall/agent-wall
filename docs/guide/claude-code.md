# Claude Code Integration

Protect your Claude Code MCP servers with Agent Wall.

## Setup

### 1. Install Agent Wall

```bash
npm install -g agent-wall
```

### 2. Generate a policy

```bash
agent-wall init
```

### 3. Update your MCP config

Edit `~/.claude/mcp_servers.json`:

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

### 4. Restart Claude Code

Close and reopen your Claude Code session. Agent Wall is now protecting your MCP server.

## Multiple Servers

Wrap each server individually:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agent-wall",
      "args": ["wrap", "--", "npx", "@modelcontextprotocol/server-filesystem", "/home/user"]
    },
    "git": {
      "command": "agent-wall",
      "args": ["wrap", "-c", "git-policy.yaml", "--", "npx", "@modelcontextprotocol/server-git"]
    }
  }
}
```

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

This will show which of your MCP servers are protected by Agent Wall.
