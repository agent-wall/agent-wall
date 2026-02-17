# Security Scanning

The `agent-wall scan` command analyzes your MCP configuration to identify unprotected servers and security risks.

## Usage

```bash
# Auto-detect config files
agent-wall scan

# Scan a specific config
agent-wall scan --config ~/.claude/mcp_servers.json

# JSON output for CI/CD pipelines
agent-wall scan --json
```

## What It Detects

### Config File Discovery

Agent Wall automatically detects MCP config files from all major clients:

| Client | Path |
|--------|------|
| Claude Code | `~/.claude/mcp_servers.json` |
| Claude Desktop (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Desktop (Windows) | `%APPDATA%\Claude\claude_desktop_config.json` |
| Claude Desktop (Linux) | `~/.config/Claude/claude_desktop_config.json` |
| Cursor | `~/.cursor/mcp.json` |
| VS Code / Copilot | `.vscode/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Cline | `~/.cline/mcp_settings.json` |
| Continue.dev | `~/.continue/config.json` |
| Generic | `.mcp.json`, `mcp.json` (current directory) |

### Risk Assessment

Each MCP server is analyzed against **48 known risky patterns** from the MCP ecosystem:

| Risk Level | Examples |
|------------|----------|
| **Critical** | Shell execution, Docker, Kubernetes, Terraform, AWS/GCP/Azure, Stripe, SSH, Vault |
| **High** | Filesystem, Playwright, Puppeteer, PostgreSQL, MySQL, MongoDB, Supabase, Cloudflare, Vercel |
| **Medium** | HTTP fetch, GitHub, GitLab, Git, Slack, email, Redis, SQLite, OpenAI, Anthropic |

### Protection Status

The scan reports whether each server is already wrapped with Agent Wall.

## Example Output

```
─── Agent Wall Security Scan ─────────────────────

  Config: /home/user/.claude/mcp_servers.json

  ⚠ filesystem
     Command: npx @modelcontextprotocol/server-filesystem /home
     HIGH: Full filesystem read/write access
     Fix: agent-wall wrap -- npx @modelcontextprotocol/server-filesystem /home

  🛡 protected-server
     Command: agent-wall wrap -- npx mcp-server
     Protected by Agent Wall ✓

  ✓ safe-tool
     Command: npx @modelcontextprotocol/server-time
     No known risks detected

─── Scan Results ───────────────────────────────
  MCP Servers: 3
  Risks found: 1
─────────────────────────────────────────────────
```
