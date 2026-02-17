# agent-wall init

Generate a starter `agent-wall.yaml` configuration file with sensible defaults.

## Usage

```bash
agent-wall init [options]
```

## Options

| Option | Description |
|--------|-------------|
| `-p, --path <path>` | Output path (default: `./agent-wall.yaml`) |
| `-f, --force` | Overwrite existing file |

## Examples

```bash
# Generate in current directory
agent-wall init

# Custom path
agent-wall init --path ./config/agent-wall.yaml

# Overwrite existing
agent-wall init --force
```

## Generated Config

The generated config includes rules for common security scenarios:

- Block SSH key and credential access
- Block environment file access  
- Block data exfiltration via shell commands
- Require approval for shell execution
- Allow read-only operations
- Global rate limiting (200 calls/minute)
