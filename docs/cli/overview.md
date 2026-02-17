# CLI Overview

Agent Wall provides a comprehensive CLI for managing MCP server security.

## Installation

```bash
npm install -g agent-wall
```

## Commands

| Command | Description |
|---------|-------------|
| [`wrap`](/cli/wrap) | Wrap an MCP server with policy enforcement |
| [`init`](/cli/init) | Generate a starter `agent-wall.yaml` config |
| [`test`](/cli/test) | Dry-run a tool call against your policy |
| [`audit`](/cli/audit) | Display and analyze audit logs |
| [`scan`](/cli/scan) | Scan MCP configurations for security risks |
| [`validate`](/cli/validate) | Validate a policy configuration file |
| [`doctor`](/cli/doctor) | Health check — verify config, environment, and MCP setup |

## Global Options

```bash
agent-wall --version    # Show version
agent-wall --help       # Show help
agent-wall <cmd> --help # Show command-specific help
```

## Quick Reference

```bash
# Protect a server (two-way: tool calls + response scanning)
agent-wall wrap -- npx @modelcontextprotocol/server-filesystem /home/user

# Generate config
agent-wall init

# Test a rule
agent-wall test --tool read_file --arg path=/home/.ssh/id_rsa

# Review audit log
agent-wall audit --log ./audit.log --filter denied

# Scan for risks
agent-wall scan

# Validate config
agent-wall validate

# Health check
agent-wall doctor
```

## Environment Variables

Agent Wall supports environment variables as fallbacks for common options:

| Variable | Description | Used by |
|----------|-------------|--------|
| `AGENT_WALL_CONFIG` | Default config file path | `wrap`, `test`, `validate`, `doctor` |
| `AGENT_WALL_LOG` | Default audit log file path | `wrap` |

Explicit CLI flags always take precedence over environment variables.

```bash
# Set once, use everywhere
export AGENT_WALL_CONFIG=/path/to/agent-wall.yaml
export AGENT_WALL_LOG=/var/log/agent-wall.log

# These now use the env vars automatically
agent-wall wrap -- npx mcp-server
agent-wall test --tool read_file --arg path=/tmp/file
agent-wall validate
```
