# agent-wall test

Dry-run a tool call against your policy rules without starting a server.

## Usage

```bash
agent-wall test [options]
```

## Options

| Option | Description |
|--------|-------------|
| `-c, --config <path>` | Path to `agent-wall.yaml` config file |
| `-t, --tool <name>` | **(Required)** Tool name to test |
| `-a, --arg <key=value>` | Tool argument (repeatable) |

Also respects the `AGENT_WALL_CONFIG` environment variable.

## Examples

```bash
# Test SSH key access → should be DENIED
agent-wall test --tool read_file --arg path=/home/.ssh/id_rsa

# Test normal file read → should be ALLOWED
agent-wall test --tool read_file --arg path=/home/user/project/README.md

# Test shell command → should be PROMPTED
agent-wall test --tool shell_exec --arg command="ls -la"

# Test with multiple arguments
agent-wall test --tool write_file --arg path=/tmp/test.txt --arg content="hello"

# Test with custom config
agent-wall test -c strict-policy.yaml --tool read_file --arg path=/etc/passwd
```

## Output

```
─── Agent Wall Policy Test ─────────────────────

  Config:  ./agent-wall.yaml
  Tool:    read_file
  Args:    path=/home/.ssh/id_rsa

  Result:  ✗ DENIED
  Rule:    block-ssh-keys
  Message: SSH key access blocked

─────────────────────────────────────────────────
```
