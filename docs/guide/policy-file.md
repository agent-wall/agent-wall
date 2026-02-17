# Policy File

Agent Wall uses a YAML configuration file to define security policies.

## File Location

Agent Wall automatically discovers config files in this order:

1. `agent-wall.yaml` (current directory)
2. `agent-wall.yml`
3. `.agent-wall.yaml`
4. `.agent-wall.yml`

You can also specify a custom path:

```bash
agent-wall wrap -c /path/to/my-policy.yaml -- npx mcp-server
```

Or use an environment variable:

```bash
export AGENT_WALL_CONFIG=/path/to/my-policy.yaml
agent-wall wrap -- npx mcp-server
```

## File Structure

```yaml
# agent-wall.yaml
version: 1
defaultAction: prompt

globalRateLimit:
  maxCalls: 200
  windowSeconds: 60

rules:
  - name: block-ssh-keys
    tool: "*"
    match:
      arguments:
        path: "**/.ssh/**"
    action: deny
    message: "SSH key access blocked"

  - name: allow-read-file
    tool: "read_file|get_file_contents"
    action: allow
```

## Fields

### `version`

**Required.** Must be `1`.

### `defaultAction`

**Required.** The action to take when no rule matches a tool call.

| Value | Description |
|-------|-------------|
| `allow` | Forward unmatched calls (permissive) |
| `deny` | Block unmatched calls (restrictive) |
| `prompt` | Ask for human approval (recommended) |

::: tip
Use `prompt` as your default action while getting started. You can switch to `deny` once you've identified all the tools your agents need.
:::

### `globalRateLimit`

**Optional.** Limits the total number of tool calls across all rules.

```yaml
globalRateLimit:
  maxCalls: 200       # Max calls allowed
  windowSeconds: 60   # Time window in seconds
```

### `responseScanning`

**Optional.** Configures response scanning — inspects what MCP servers return before it reaches the AI agent.

```yaml
responseScanning:
  enabled: true            # Enable/disable (default: true)
  maxResponseSize: 5242880 # 5MB limit
  oversizeAction: redact   # "block" or "redact" (truncate)
  detectSecrets: true      # API keys, tokens, private keys
  detectPII: false         # Email, phone, SSN, credit cards (opt-in)
  patterns:                # Custom regex patterns
    - name: internal-urls
      pattern: "https?://internal\\.[a-z]+\\.corp"
      action: redact
      message: "Internal URL detected"
      category: custom
```

See [Response Scanning](/guide/response-scanning) for full documentation.

### `security`

**Optional.** Configures security hardening modules that run alongside the policy engine.

```yaml
security:
  injectionDetection:
    enabled: true          # Detect prompt injection in arguments
    sensitivity: medium    # low, medium, high
    # customPatterns: []   # Additional regex patterns
    # excludeTools: []     # Tools to skip
  egressControl:
    enabled: true
    blockPrivateIPs: true       # RFC1918, loopback, link-local
    blockMetadataEndpoints: true # AWS/GCP/Azure metadata SSRF
    # allowedDomains: []        # Allowlist mode (only these pass)
    # blockedDomains: []        # Blocklist mode
  killSwitch:
    enabled: true
    checkFile: true             # Watch for .agent-wall-kill file
    # pollIntervalMs: 1000
  chainDetection:
    enabled: true               # Detect suspicious tool call sequences
  signing: false                # HMAC-SHA256 audit log signing
  # signingKey: "..."           # Auto-generated if not provided
```

### `rules`

**Required.** An array of policy rules evaluated in order (first match wins).

See [Rules](/guide/rules) for detailed documentation.

## Generating a Config

```bash
# Generate with sensible defaults
agent-wall init

# Generate at a custom path
agent-wall init --path ./config/agent-wall.yaml

# Overwrite existing
agent-wall init --force
```

## Validating a Config

```bash
# Validate the auto-discovered config
agent-wall validate

# Validate a specific file
agent-wall validate --config ./agent-wall.yaml
```

## Hot-Reload

Agent Wall watches your policy file for changes. When you edit and save `agent-wall.yaml`, the policy is automatically reloaded without restarting the proxy. This makes it easy to iterate on rules while Agent Wall is running.

## Built-in Defaults

When no config file is found, Agent Wall uses built-in defaults that:

- **Block** access to `.ssh/`, `.env`, `.pem`, `.key`, credential files
- **Block** `curl`, `wget`, `netcat` in shell commands
- **Prompt** for file deletion and shell execution
- **Allow** file reading, directory listing, search operations
- **Rate limit** 200 calls/minute globally
