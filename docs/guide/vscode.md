# VS Code / GitHub Copilot Integration

Protect your VS Code MCP servers with Agent Wall. VS Code has supported MCP since version 1.99.

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

VS Code uses a workspace-level `.vscode/mcp.json` file:

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

### 4. Reload VS Code

Reload the window (`Ctrl+Shift+P` → "Reload Window"). Agent Wall is now active.

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

## Multiple Servers

Wrap each server individually:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agent-wall",
      "args": ["wrap", "--", "npx", "@modelcontextprotocol/server-filesystem", "/home/user"]
    },
    "github": {
      "command": "agent-wall",
      "args": ["wrap", "--", "npx", "@modelcontextprotocol/server-github"]
    }
  }
}
```

## Verify Protection

```bash
agent-wall scan
```
