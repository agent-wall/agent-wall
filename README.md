# Agent Wall

**Security firewall for AI agents.** Intercepts MCP tool calls, enforces policies, blocks attacks.

> *"Cloudflare for AI agents"* — Zero-config protection for any MCP server.

[![CI](https://github.com/agent-wall/agent-wall/actions/workflows/ci.yml/badge.svg)](https://github.com/agent-wall/agent-wall/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![npm](https://img.shields.io/npm/v/agent-wall)](https://www.npmjs.com/package/agent-wall)

## The Problem

AI agents can now execute tools — read files, run shell commands, query databases, make HTTP requests. Without guardrails, a single prompt injection can:

1. **Read** your SSH keys, `.env` files, credentials
2. **Exfiltrate** data via `curl`, `wget`, or DNS tunneling
3. **Execute** arbitrary shell commands with your permissions
4. **Chain** multiple tools to escalate from read to exfil to execute

Agent Wall sits between the MCP client and server, enforcing a YAML policy on every tool call — both requests going in and responses coming out.

```
MCP Client  ←→  Agent Wall Proxy  ←→  MCP Server
                      ↕
               agent-wall.yaml
               + security modules
               + response scanner
```

## Quick Start

```bash
# Install globally
npm install -g @agent-wall/cli

# Generate a starter policy
agent-wall init

# Wrap any MCP server
agent-wall wrap -- npx @modelcontextprotocol/server-filesystem /home/user

# With real-time dashboard
agent-wall wrap --dashboard -- npx @modelcontextprotocol/server-filesystem /home/user
```

**That's it.** Agent Wall is now protecting your MCP server.

## 30-Second Integration

Replace your MCP config entry to wrap any server:

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

Every `tools/call` request runs through a **5-step inbound pipeline**:

```
1. Kill Switch     — Emergency deny-all (file/signal/programmatic)
2. Injection       — 30+ patterns detect prompt injection attacks
3. Egress Control  — Block private IPs, SSRF, metadata endpoints
4. Policy Engine   — YAML rules (first-match-wins, glob, rate limiting)
5. Chain Detection — Suspicious multi-step patterns (read→exfil, write→exec)
```

Responses run through an **outbound scanner**:

```
6. Response Scanner — 14 secret patterns, 5 PII patterns, custom regex
                      Actions: pass / redact / block
```

## Policy Configuration

Rules are defined in `agent-wall.yaml` — first match wins:

```yaml
version: 1
defaultAction: prompt

globalRateLimit:
  maxCalls: 200
  windowSeconds: 60

security:
  injectionDetection:
    enabled: true
    sensitivity: medium   # low | medium | high
  egressControl:
    enabled: true
    blockPrivateIPs: true
  killSwitch:
    enabled: true
  chainDetection:
    enabled: true

responseScanning:
  enabled: true
  maxResponseSize: 5242880
  detectSecrets: true
  detectPII: false

rules:
  # Block credential access
  - name: block-ssh-keys
    tool: "*"
    match:
      arguments:
        path: "**/.ssh/**"
    action: deny
    message: "SSH key access blocked"

  # Block exfiltration vectors
  - name: block-curl-exfil
    tool: "shell_exec|run_command|execute_command"
    match:
      arguments:
        command: "*curl *"
    action: deny

  # Require approval for shell commands
  - name: approve-shell-exec
    tool: "shell_exec|run_command|execute_command|bash"
    action: prompt

  # Allow safe reads
  - name: allow-read-file
    tool: "read_file|get_file_contents|view_file"
    action: allow
```

### Rule Features

| Feature | Example | Description |
|---------|---------|-------------|
| **Glob patterns** | `*delete*` | Match tool names with wildcards |
| **Pipe alternatives** | `shell_exec\|run_command` | Match multiple tool names |
| **Argument matching** | `path: "**/.ssh/**"` | Pattern match against arguments |
| **Rate limiting** | `maxCalls: 10, windowSeconds: 60` | Per-rule and global rate limits |
| **Three actions** | `allow`, `deny`, `prompt` | Forward, block, or ask human |
| **Hot-reload** | Edit yaml, auto-reloads | No restart needed |

## Real-Time Dashboard

Monitor security events live in your browser:

```bash
agent-wall wrap --dashboard -- npx mcp-server
# → Dashboard at http://localhost:61100
```

- Live event feed with allow/deny/prompt color coding
- Stats cards (total, forwarded, denied, attacks, scanned)
- Attack panel grouped by category (injections, SSRF, chains)
- Rule hit table (sortable)
- Kill switch toggle (with confirmation)
- Audit log search

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

```bash
# Wrap with dashboard and audit logging
agent-wall wrap --dashboard --log-file ./audit.log -- npx mcp-server

# Dry-run preview
agent-wall wrap --dry-run -- npx mcp-server

# Test a tool call
agent-wall test --tool read_file --arg path=/home/.ssh/id_rsa
# → DENIED by rule "block-ssh-keys"

# View denied entries from audit log
agent-wall audit --log ./audit.log --filter denied --last 20

# Scan for unprotected MCP servers
agent-wall scan

# Validate config
agent-wall validate
```

## Response Scanning

Agent Wall inspects server responses before they reach the LLM:

- **14 built-in secret patterns** — AWS keys, GitHub tokens, OpenAI keys, JWTs, private keys, database URLs, passwords, certificates
- **5 PII patterns** — email, phone, SSN, credit card, IP address (opt-in)
- **Custom patterns** — Add your own regex via YAML config
- **Three actions** — `pass` (log only), `redact` (replace with `[REDACTED]`), `block` (error to client)
- **Size limits** — Configurable max response size with oversize action

## Built-in Default Policy

Without a config file, Agent Wall ships with sensible defaults:

- **Block** access to `.ssh/`, `.env`, `.pem`, `.key`, `.pfx`, `.p12`, credential files
- **Block** `curl`, `wget`, `netcat`, `powershell`, `pwsh` in shell commands
- **Block** DNS exfiltration vectors (`nslookup`, `dig`, `host`)
- **Detect** prompt injection attacks (30+ patterns)
- **Block** SSRF to private IPs and cloud metadata endpoints
- **Detect** suspicious tool call chains (read→exfil, write→execute)
- **Prompt** for shell execution and file deletion
- **Allow** file reading, directory listing, search operations
- **Scan** responses for leaked secrets and API keys
- **Rate limit** 200 calls/minute globally

## Architecture

```
packages/
  core/        @agent-wall/core       — Proxy engine, policy, security modules
  cli/         agent-wall             — CLI (wrap, init, test, audit, scan, validate, doctor)
  dashboard/   @agent-wall/dashboard  — React SPA for real-time monitoring
  docs/        VitePress documentation site
```

**Zero dependencies on MCP SDK** — Agent Wall implements its own JSON-RPC parsing so it works with any MCP version.

Key modules:
- **StdioProxy** — Two-way interception proxy with 5-step defense pipeline
- **PolicyEngine** — First-match-wins rule evaluator (glob patterns, rate limiting, strict mode)
- **ResponseScanner** — Secret/PII detection with ReDoS protection
- **InjectionDetector** — 30+ prompt injection patterns (configurable sensitivity)
- **EgressControl** — URL/SSRF protection (RFC1918, metadata, hex/octal IP obfuscation)
- **KillSwitch** — Emergency deny-all (file-based, signal-based, programmatic)
- **ChainDetector** — Multi-step attack pattern detection
- **DashboardServer** — WebSocket + HTTP server for browser dashboard
- **AuditLogger** — HMAC-SHA256 signed JSON lines with log rotation
- **PolicyLoader** — YAML config with Zod validation, auto-discovery, hot-reload

## Testing


```bash
pnpm test    # Run all tests
pnpm build   # Build all packages
```

## Development

```bash
# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests
pnpm test

# Dev docs server
pnpm docs:dev
```

## Contributing

Contributions are welcome! Please read the [Contributing Guide](CONTRIBUTING.md) before submitting a PR.

## License

[MIT](LICENSE) — Built with obsession by the Agent Wall contributors.
