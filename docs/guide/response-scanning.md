# Response Scanning

Agent Wall doesn't just control what goes **in** — it also inspects what comes **out**. The response scanner analyzes MCP server responses before they reach the AI agent, catching leaked secrets, sensitive data, and oversized payloads.

## Why Response Scanning?

Even with perfect tool call policies, MCP servers can return dangerous content:

- A `read_file` call on a config file might **return database credentials** in the response
- A `search_files` call might **return private keys** found in search results
- A `shell_exec` call might **dump environment variables** containing API keys
- A compromised server might **inject secrets** into its responses

Agent Wall scans every tool response before it reaches the LLM.

## Configuration

Add the `responseScanning` section to your `agent-wall.yaml`:

```yaml
version: 1
defaultAction: prompt

responseScanning:
  enabled: true             # Enable/disable (default: true)
  maxResponseSize: 5242880  # 5MB limit (0 = no limit)
  oversizeAction: redact    # "block" or "redact" (truncate)
  detectSecrets: true       # Built-in secret detection
  detectPII: false          # PII detection (opt-in)
  patterns:                 # Custom patterns (optional)
    - name: internal-urls
      pattern: "https?://internal\\.[a-z]+\\.corp"
      action: redact
      message: "Internal URL detected"
      category: custom

rules:
  # ... your rules
```

## Built-in Secret Detection

When `detectSecrets: true` (the default), Agent Wall detects:

| Pattern | What it detects | Action |
|---------|----------------|--------|
| `aws-access-key` | AWS Access Key IDs (`AKIA...`) | redact |
| `aws-secret-key` | AWS Secret Access Keys | redact |
| `github-token` | GitHub tokens (`ghp_`, `gho_`, etc.) | redact |
| `openai-api-key` | OpenAI API keys (`sk-...`) | redact |
| `generic-api-key` | Generic `api_key=`, `api_secret=` patterns | redact |
| `bearer-token` | Bearer tokens in auth headers | redact |
| `jwt-token` | JWT tokens (`eyJ...`) | redact |
| `private-key` | RSA/EC/DSA/OPENSSH private keys | **block** |
| `certificate` | X.509 certificates | redact |
| `database-url` | Connection strings with credentials | redact |
| `password-assignment` | `password=`, `passwd:` patterns | redact |

::: warning
Private keys trigger a **block** action — the entire response is replaced with an error. This is intentional: once a private key reaches the LLM's context, it may be included in logs, summaries, or further API calls.
:::

## PII Detection (Opt-in)

When `detectPII: true`, Agent Wall also scans for personally identifiable information:

| Pattern | What it detects | Action |
|---------|----------------|--------|
| `email-address` | Email addresses | redact |
| `phone-number` | US phone numbers | redact |
| `ssn` | Social Security Numbers | **block** |
| `credit-card` | Credit card numbers (Visa, MC, Amex, Discover) | **block** |
| `ip-address` | IPv4 addresses | pass (informational) |

::: tip
PII detection is **off by default** because it can produce false positives in code-heavy responses. Enable it when your agents work with user data.
:::

## Response Actions

| Action | Behavior |
|--------|----------|
| `pass` | Forward response as-is (informational findings only) |
| `redact` | Replace matched content with `[REDACTED:pattern-name]` |
| `block` | Return an error to the client — the response never reaches the LLM |

When multiple patterns match, the **highest severity wins**: `block` > `redact` > `pass`.

## Custom Patterns

Define your own regex patterns for organization-specific data:

```yaml
responseScanning:
  enabled: true
  detectSecrets: true
  patterns:
    # Block responses containing internal database hostnames
    - name: internal-db
      pattern: "db-prod-[a-z0-9]+\\.internal\\.company\\.com"
      action: block
      message: "Internal database hostname detected"
      category: infrastructure

    # Redact internal API endpoints
    - name: internal-api
      pattern: "https?://api\\.internal\\.[a-z]+\\.corp/v[0-9]+"
      action: redact
      message: "Internal API endpoint detected"
      category: infrastructure

    # Flag responses with [CONFIDENTIAL] markers
    - name: confidential
      pattern: "\\[CONFIDENTIAL\\]"
      action: block
      message: "Confidential content detected"
      category: compliance
```

### Pattern Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Unique identifier for the pattern |
| `pattern` | Yes | Regex pattern to match |
| `action` | Yes | `pass`, `redact`, or `block` |
| `flags` | No | Regex flags (default: `gi`) |
| `message` | No | Human-readable description |
| `category` | No | Category for audit logs |

## Response Size Limits

Prevent context window stuffing by limiting response size:

```yaml
responseScanning:
  maxResponseSize: 5242880  # 5MB
  oversizeAction: redact    # or "block"
```

- **`redact`** (default): Truncates the response to the limit and appends a notice
- **`block`**: Returns an error — the oversized response never reaches the LLM

Set `maxResponseSize: 0` to disable the size check.

## How It Works Internally

1. When a `tools/call` request is **allowed** (or approved via prompt), Agent Wall tracks it by its JSON-RPC `id`
2. When the MCP server returns a response with that `id`, Agent Wall intercepts it
3. The response scanner extracts all text content from the MCP result (`content[].text`)
4. All compiled regex patterns are executed against the text
5. Findings are collected with match counts and categories
6. The highest-severity action is applied (`block` > `redact` > `pass`)
7. For `redact`: each matched pattern is replaced with `[REDACTED:pattern-name]`
8. For `block`: a JSON-RPC error is sent to the client instead

## Session Summary

When the proxy exits, the session summary now includes response scanning stats:

```
─── Agent Wall Session Summary ────────────────────
  Total calls:       42
  Forwarded:         35
  Denied:            5
  Prompted:          2
  Responses scanned: 35
  Resp. blocked:     1
  Resp. redacted:    3
───────────────────────────────────────────────────
```

## Audit Logging

Response scan findings are logged with `direction: "response"`:

```json
{
  "timestamp": "2026-02-11T10:30:00.000Z",
  "sessionId": "ag-abc123",
  "direction": "response",
  "method": "tools/call",
  "tool": "read_file",
  "verdict": {
    "action": "deny",
    "rule": "__response_scanner__",
    "message": "Response blocked: private-key: Private key detected in response"
  }
}
```

## Examples

### Production-safe config

```yaml
responseScanning:
  enabled: true
  maxResponseSize: 2097152  # 2MB
  oversizeAction: block
  detectSecrets: true
  detectPII: true
  patterns:
    - name: internal-hosts
      pattern: "[a-z]+-prod-[0-9]+\\.internal\\."
      action: redact
      message: "Internal hostname"
```

### Development config (relaxed)

```yaml
responseScanning:
  enabled: true
  maxResponseSize: 10485760  # 10MB
  oversizeAction: redact
  detectSecrets: true
  detectPII: false
```

### Disable response scanning

```yaml
responseScanning:
  enabled: false
```

## Programmatic Usage

```typescript
import { ResponseScanner, createDefaultScanner } from "@agent-wall/core";

// Use defaults (secrets ON, PII OFF, 5MB limit)
const scanner = createDefaultScanner();

// Or customize
const scanner = new ResponseScanner({
  detectSecrets: true,
  detectPII: true,
  maxResponseSize: 1024 * 1024,  // 1MB
  patterns: [
    { name: "custom", pattern: "SECRET_DATA", action: "block" },
  ],
});

// Scan raw text
const result = scanner.scan("response text here");
console.log(result.clean);     // true/false
console.log(result.action);    // "pass" | "redact" | "block"
console.log(result.findings);  // Array of findings

// Scan an MCP response result
const mcpResult = { content: [{ type: "text", text: "..." }] };
const result = scanner.scanMcpResponse(mcpResult);
```
