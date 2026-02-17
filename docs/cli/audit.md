# agent-wall audit

Display and analyze audit logs.

## Usage

```bash
agent-wall audit [options]
```

## Options

| Option | Description |
|--------|-------------|
| `-l, --log <path>` | **(Required)** Path to the audit log file |
| `-f, --filter <action>` | Filter by action: `allowed`, `denied`, `prompted`, `all` (default: `all`) |
| `-n, --last <count>` | Show only the last N entries |
| `--json` | Output raw JSON |

## Examples

```bash
# View all entries
agent-wall audit --log ./audit.log

# View only denied calls
agent-wall audit --log ./audit.log --filter denied

# Last 20 entries
agent-wall audit --log ./audit.log --last 20

# JSON output for scripting
agent-wall audit --log ./audit.log --json | jq '.tool'
```
