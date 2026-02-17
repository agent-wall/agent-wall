# agent-wall wrap

Wrap an MCP server with Agent Wall policy enforcement.

## Usage

```bash
agent-wall wrap [options] -- <command> [args...]
```

## Options

| Option | Description |
|--------|-------------|
| `-c, --config <path>` | Path to `agent-wall.yaml` config file |
| `-l, --log-file <path>` | Path to write audit log (JSON lines) |
| `-s, --silent` | Suppress Agent Wall output (only MCP protocol on stdout) |
| `--dry-run` | Preview policy evaluation without starting the server |
| `-d, --dashboard` | Launch the real-time security dashboard |
| `--dashboard-port <port>` | Dashboard port (default: `61100`) |

Also respects `AGENT_WALL_CONFIG` and `AGENT_WALL_LOG` environment variables as fallbacks.

## Examples

```bash
# Basic usage
agent-wall wrap -- npx @modelcontextprotocol/server-filesystem /home/user

# Custom config
agent-wall wrap -c custom-policy.yaml -- node my-server.js

# With audit logging  
agent-wall wrap --log-file ./audit.log -- npx mcp-server

# Silent mode (for Claude Desktop or non-interactive contexts)
agent-wall wrap --silent -- npx mcp-server

# Dry-run: preview rules without starting
agent-wall wrap --dry-run -- npx mcp-server

# Launch with real-time dashboard
agent-wall wrap --dashboard -- npx mcp-server

# Dashboard on custom port
agent-wall wrap --dashboard --dashboard-port 8080 -- node my-server.js
```

## How it works

1. Loads the policy configuration (from file or built-in defaults)
2. Creates the response scanner from the `responseScanning` config section
3. Initializes security modules (injection detection, egress control, kill switch, chain detection)
4. Spawns the MCP server as a child process
5. Starts the dashboard server if `--dashboard` is specified
6. Intercepts all stdin/stdout JSON-RPC messages
7. **Inbound**: Runs the 5-step defense pipeline (kill switch → injection → egress → policy → chain)
8. Forwards allowed calls, blocks denied calls, prompts for approval
9. **Outbound**: Scans tool call responses for secrets, PII, and oversize content
10. Blocks or redacts responses with findings, passes clean responses through
11. Passes all other messages through untouched

## Dry Run Mode

The `--dry-run` flag shows your loaded policy without starting the server:

```
╔══════════════════════════════════════════════════╗
║  Agent Wall — Security Firewall for AI Agents    ║
╠══════════════════════════════════════════════════╣
║  Policy: ./agent-wall.yaml
║  Rules:  8 loaded
║  Scanner: response scanning ON
║  Server: npx mcp-server
╚══════════════════════════════════════════════════╝

  --dry-run mode: preview only, server will not start

  Default action: prompt
  Rate limit:     200 calls / 60s
  Rules loaded:   8

  ✗ block-ssh-keys → deny (tool: *)
  ✗ block-exfiltration → deny (tool: shell_exec|run_command)
  ? approve-shell → prompt (tool: shell_exec|bash)
  ✓ allow-reads → allow (tool: read_file|get_file_contents)
```
