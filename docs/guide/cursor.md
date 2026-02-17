# Cursor Integration

Protect your Cursor MCP servers with Agent Wall.

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

Edit `~/.cursor/mcp.json`:

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

### 4. Restart Cursor

Restart your Cursor editor. Agent Wall is now protecting your MCP server.

## Per-Project Policies

Use different policies for different projects:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agent-wall",
      "args": ["wrap", "-c", "/path/to/project/agent-wall.yaml", "--", "npx", "@modelcontextprotocol/server-filesystem", "/home/user"]
    }
  }
}
```
