# agent-wall scan

Scan your MCP configuration for security risks. Detects unprotected servers, risky tool patterns, and missing Agent Wall protection.

## Usage

```bash
agent-wall scan [options]
```

## Options

| Option | Description |
|--------|-------------|
| `-c, --config <path>` | Path to MCP config file (auto-detects if omitted) |
| `--json` | Output results as JSON (to stdout) |

## Examples

```bash
# Auto-detect MCP configs
agent-wall scan

# Scan specific config
agent-wall scan --config ~/.claude/mcp_servers.json

# JSON output for CI/CD or scripting
agent-wall scan --json
agent-wall scan --config mcp.json --json | jq '.servers[] | select(.risks | length > 0)'
```

## Auto-Detection

Without `--config`, Agent Wall automatically looks for MCP config files from all major clients:

| Client | Config Path |
|--------|------------|
| Claude Code | `~/.claude/mcp_servers.json` |
| Claude Desktop (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Desktop (Windows) | `%APPDATA%\Claude\claude_desktop_config.json` |
| Claude Desktop (Linux) | `~/.config/Claude/claude_desktop_config.json` |
| Cursor | `~/.cursor/mcp.json` |
| VS Code / Copilot | `.vscode/mcp.json` (workspace-level) |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Cline | `~/.cline/mcp_settings.json` |
| Continue.dev | `~/.continue/config.json` |
| Generic | `.mcp.json`, `mcp.json` (current directory) |

## Risk Patterns

Agent Wall recognizes **48 risky tool patterns** across these categories:

| Category | Risk Level | Examples |
|----------|-----------|----------|
| Execution | Critical | `shell`, `bash`, `exec`, `terminal` |
| Infrastructure | Critical | `docker`, `kubernetes`, `terraform`, `aws`, `gcp`, `azure` |
| Payment / Secrets | Critical | `stripe`, `razorpay`, `vault`, `1password` |
| Remote Access | Critical | `ssh`, `rdp` |
| Filesystem | High | `filesystem` |
| Browser Automation | High | `playwright`, `puppeteer`, `browser` |
| Databases | High | `postgres`, `mysql`, `mongodb`, `supabase`, `snowflake` |
| Cloud Platforms | High | `cloudflare`, `vercel`, `netlify` |
| Source Control | Medium | `github`, `gitlab`, `git` |
| Communication | Medium | `slack`, `email`, `gmail`, `discord` |
| Network | Medium | `fetch`, `redis`, `sqlite` |
| AI APIs | Medium | `openai`, `anthropic` |

## JSON Output

With `--json`, scan outputs structured results to stdout:

```json
{
  "servers": [
    {
      "name": "filesystem",
      "configFile": "/home/user/.claude/mcp_servers.json",
      "command": "npx @modelcontextprotocol/server-filesystem /home",
      "protected": false,
      "risks": [
        { "level": "high", "reason": "Full filesystem read/write access" }
      ]
    }
  ],
  "totalRisks": 1
}
```
