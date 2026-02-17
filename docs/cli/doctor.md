# agent-wall doctor

Health check — verify your config, environment, and MCP setup are all working correctly.

## Usage

```bash
agent-wall doctor [options]
```

## Options

| Option | Description |
|--------|-------------|
| `-c, --config <path>` | Path to `agent-wall.yaml` config file |

Also respects the `AGENT_WALL_CONFIG` environment variable.

## Checks Performed

| Check | What it verifies |
|-------|-----------------|
| **Node.js version** | Node.js >= 18 is installed |
| **Policy config** | Config file loads, parses, and the policy engine initializes |
| **MCP clients found** | Detects installed MCP client configs (Claude, Cursor, VS Code, Windsurf, Cline) |
| **Env overrides** | Reports any `AGENT_WALL_CONFIG` or `AGENT_WALL_LOG` environment variables |

## Examples

```bash
# Run all health checks
agent-wall doctor

# Check a specific config
agent-wall doctor --config ./custom-policy.yaml
```

## Example Output

```
─── Agent Wall Doctor ───────────────────────────

  ✓ Node.js version
    v22.0.0

  ✓ Policy config
    ./agent-wall.yaml (11 rules)

  ✓ MCP clients found
    Claude Code, Cursor

  ✓ Env overrides
    AGENT_WALL_CONFIG

─── Summary ────────────────────────────────────
  All checks passed. Agent Wall is ready.
─────────────────────────────────────────────────
```

### With issues

```
─── Agent Wall Doctor ───────────────────────────

  ✓ Node.js version
    v22.0.0

  ✗ Policy config
    Policy file not found: ./agent-wall.yaml

  ✗ MCP clients found
    None detected (run 'agent-wall scan' for details)

  ✓ Env overrides
    None set

─── Summary ────────────────────────────────────
  2 issue(s) found:
    • Policy config: Policy file not found
    • MCP clients found: None detected
─────────────────────────────────────────────────
```
