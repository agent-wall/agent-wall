# Claude Desktop Integration

Protect your Claude Desktop MCP servers with Agent Wall.

## Setup

### 1. Install Agent Wall

```bash
npm install -g @agent-wall/cli
```

### 2. Generate a policy

```bash
agent-wall init
```

### 3. Update your config

Edit your Claude Desktop config file:

| Platform | Path |
|----------|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |

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
      "args": ["wrap", "--silent", "--", "npx", "@modelcontextprotocol/server-filesystem", "/home/user"]
    }
  }
}
```

::: tip
Use `--silent` with Claude Desktop since there's no terminal to display the Agent Wall banner.
:::

### 4. Restart Claude Desktop

Quit and reopen Claude Desktop. Agent Wall is now active.
