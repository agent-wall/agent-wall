# agent-wall validate

Validate your policy configuration file for syntax errors, schema issues, and best practice warnings.

## Usage

```bash
agent-wall validate [options]
```

## Options

| Option | Description |
|--------|-------------|
| `-c, --config <path>` | Path to `agent-wall.yaml` config file (auto-discovers if omitted) |

Also respects the `AGENT_WALL_CONFIG` environment variable.

## Examples

```bash
# Validate auto-discovered config
agent-wall validate

# Validate specific file
agent-wall validate --config ./custom-policy.yaml
```

## Checks Performed

- **YAML syntax** — Valid YAML parsing
- **Schema validation** — Zod schema compliance (version, actions, rules)
- **Version check** — Config version is supported
- **Default action** — Valid action value (allow, deny, prompt)
- **Rate limits** — Positive values for maxCalls and windowSeconds
- **Rule names** — No duplicates, all rules named (recommended)
- **Tool patterns** — No spaces in tool patterns (use `|` separator)
- **Engine initialization** — Policy engine can be constructed from config

## Example Output

```
─── Agent Wall Config Validation ─────────────────

  ✓ Config loaded: ./agent-wall.yaml
  ✓ Version: 1
  ✓ Default action: prompt
  ✓ Global rate limit: 200 calls / 60s
  ✓ Rules: 8 loaded
  ✓ Policy engine: OK

  ✓ Config is valid — no issues found
```

### With warnings

```
─── Agent Wall Config Validation ─────────────────

  ✓ Config loaded: ./agent-wall.yaml
  ✓ Version: 1
  ✓ Default action: prompt
  ✓ Rules: 5 loaded
  ⚠ Rule at index 2 has no name (recommended for audit logs)
  ⚠ Duplicate rule name: "allow-reads"
  ✓ Policy engine: OK

  2 warning(s), 0 errors — config is valid
```
