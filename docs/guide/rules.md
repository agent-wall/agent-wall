# Rules

Rules are the core of Agent Wall's policy engine. They define which tool calls are allowed, denied, or require human approval.

## Rule Structure

```yaml
rules:
  - name: block-ssh-keys       # Unique identifier (recommended)
    tool: "*"                   # Tool name pattern
    match:                      # Optional: argument matching
      arguments:
        path: "**/.ssh/**"
    action: deny                # allow | deny | prompt
    message: "SSH key blocked"  # Optional: custom deny message
    rateLimit:                  # Optional: per-rule rate limit
      maxCalls: 10
      windowSeconds: 60
```

## Fields

### `name`

A human-readable identifier for the rule. Used in audit logs and when testing policies.

### `tool`

A pattern to match against the tool name in the MCP `tools/call` request.

| Pattern | Matches |
|---------|---------|
| `"*"` | Any tool |
| `"read_file"` | Exactly `read_file` |
| `"*delete*"` | Any tool containing "delete" |
| `"shell_exec\|run_command\|bash"` | Any of the listed tools (pipe-separated) |

### `match`

Optional conditions that must also be true for the rule to match.

#### `match.arguments`

Match against the tool call's arguments using glob patterns:

```yaml
match:
  arguments:
    path: "**/.ssh/**"       # Glob pattern
    command: "*curl *"       # Wildcard matching
```

Multiple argument patterns must ALL match (AND logic).

### `action`

| Action | Behavior |
|--------|----------|
| `allow` | Forward the tool call to the MCP server |
| `deny` | Block the call, return an error to the client |
| `prompt` | Show the call details and ask the human to approve/deny |

### `message`

Custom message included in the deny response. Only used with `action: deny`.

### `rateLimit`

Per-rule rate limiting:

```yaml
rateLimit:
  maxCalls: 10         # Max calls allowed for this rule
  windowSeconds: 60    # Time window
```

## Evaluation Order

Rules are evaluated **top to bottom** — the first matching rule wins. This means:

```yaml
rules:
  # ❶ Most specific rules first
  - name: allow-project-files
    tool: "read_file"
    match:
      arguments:
        path: "/home/user/project/**"
    action: allow

  # ❷ Then broader restrictions
  - name: block-sensitive
    tool: "*"
    match:
      arguments:
        path: "*/.ssh/**"
    action: deny

  # ❸ General rules last
  - name: prompt-everything-else
    tool: "*"
    action: prompt
```

::: warning
If no rule matches and no `defaultAction` is set, the call will require **prompt** approval by default (fail-secure without being disruptive).
:::

## Common Patterns

### Block credential access

```yaml
- name: block-credentials
  tool: "*"
  match:
    arguments:
      path: "**/.ssh/**|**/.env*|*credentials*|**/*.pem|**/*.key"
  action: deny
  message: "Credential access blocked"
```

### Block data exfiltration

```yaml
- name: block-exfiltration
  tool: "shell_exec|run_command|execute_command"
  match:
    arguments:
      command: "*curl *|*wget *|*nc *|*netcat *"
  action: deny
  message: "Potential data exfiltration blocked"
```

### Approve destructive operations

```yaml
- name: approve-destructive
  tool: "*delete*|*remove*|*drop*"
  action: prompt
```

### Rate limit API calls

```yaml
- name: limit-api-calls
  tool: "fetch|http_request"
  action: allow
  rateLimit:
    maxCalls: 30
    windowSeconds: 60
```

### Allow safe operations

```yaml
- name: allow-reads
  tool: "read_file|get_file_contents|list_directory|search_files"
  action: allow
```
