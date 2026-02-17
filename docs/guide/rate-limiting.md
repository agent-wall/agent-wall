# Rate Limiting

Agent Wall supports both global and per-rule rate limits to prevent runaway agents from overwhelming your systems.

## Global Rate Limit

Controls the total number of tool calls across all tools:

```yaml
globalRateLimit:
  maxCalls: 200       # Maximum calls allowed
  windowSeconds: 60   # Rolling time window in seconds
```

When the global rate limit is exceeded, further tool calls are denied until the window resets.

## Per-Rule Rate Limits

Apply rate limits to specific tool patterns:

```yaml
rules:
  - name: limit-shell
    tool: "shell_exec|run_command|bash"
    action: allow
    rateLimit:
      maxCalls: 10
      windowSeconds: 60

  - name: limit-http
    tool: "fetch|http_request"
    action: allow
    rateLimit:
      maxCalls: 30
      windowSeconds: 60
```

## How It Works

Rate limits use a **sliding window** algorithm:

1. Each tool call's timestamp is recorded
2. When a new call arrives, expired timestamps (outside the window) are removed
3. If the remaining count exceeds `maxCalls`, the call is **denied**

## Rate Limit Priority

1. **Global rate limit** is checked **first** — before any rule matching
2. **Per-rule rate limits** are checked when a rule matches, before the action is applied
3. If either limit is exceeded, the call is **denied** regardless of the rule action

## Example: Defense in Depth

```yaml
# Global: no more than 200 calls/minute total
globalRateLimit:
  maxCalls: 200
  windowSeconds: 60

rules:
  # Shell commands: max 5/minute  
  - name: limit-shell
    tool: "shell_exec|run_command|bash"
    action: prompt
    rateLimit:
      maxCalls: 5
      windowSeconds: 60

  # File writes: max 20/minute
  - name: limit-writes
    tool: "write_file|edit_file|create_file"
    action: allow
    rateLimit:
      maxCalls: 20
      windowSeconds: 60

  # Everything else: allowed within global limit
  - name: allow-rest
    tool: "*"
    action: allow
```
