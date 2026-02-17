# Default Policy

When no configuration file is found, Agent Wall uses a sensible built-in policy that provides immediate protection.

## Built-in Rules

```yaml
version: 1
defaultAction: prompt

globalRateLimit:
  maxCalls: 200
  windowSeconds: 60

responseScanning:
  enabled: true
  maxResponseSize: 5242880  # 5MB
  oversizeAction: redact
  detectSecrets: true
  detectPII: false

rules:
  # ── Block: Credential Access ────────────────────────
  - name: block-ssh-keys
    tool: "*"
    match:
      arguments:
        path: "**/.ssh/**|**/.ssh"
    action: deny
    message: "Access to SSH keys is blocked by default policy"

  - name: block-env-files
    tool: "*"
    match:
      arguments:
        path: "**/.env*"
    action: deny
    message: "Access to .env files is blocked by default policy"

  - name: block-credential-files
    tool: "*"
    match:
      arguments:
        path: "*credentials*|**/*.pem|**/*.key|**/*.pfx|**/*.p12"
    action: deny
    message: "Access to credential files is blocked by default policy"

  # ── Block: Exfiltration Patterns ────────────────────
  - name: block-curl-exfil
    tool: "shell_exec|run_command|execute_command"
    match:
      arguments:
        command: "*curl *"
    action: deny
    message: "Shell commands with curl are blocked — potential data exfiltration"

  - name: block-wget-exfil
    tool: "shell_exec|run_command|execute_command"
    match:
      arguments:
        command: "*wget *"
    action: deny
    message: "Shell commands with wget are blocked — potential data exfiltration"

  - name: block-netcat-exfil
    tool: "shell_exec|run_command|execute_command"
    match:
      arguments:
        command: "*nc *|*ncat *|*netcat *"
    action: deny
    message: "Shell commands with netcat are blocked — potential data exfiltration"

  - name: block-powershell-exfil
    tool: "shell_exec|run_command|execute_command|bash"
    match:
      arguments:
        command: "*powershell*|*pwsh*|*Invoke-WebRequest*|*Invoke-RestMethod*|*DownloadString*|*DownloadFile*|*Start-BitsTransfer*"
    action: deny
    message: "PowerShell command blocked — potential data exfiltration"

  - name: block-dns-exfil
    tool: "shell_exec|run_command|execute_command|bash"
    match:
      arguments:
        command: "*nslookup *|*dig *|*host *"
    action: deny
    message: "DNS lookup command blocked — potential DNS exfiltration vector"

  # ── Prompt: Scripting One-Liners ────────────────────
  - name: approve-script-exec
    tool: "shell_exec|run_command|execute_command|bash"
    match:
      arguments:
        command: "*python* -c *|*python3* -c *|*ruby* -e *|*perl* -e *|*node* -e *|*node* --eval*"
    action: prompt
    message: "Inline script execution requires approval — may be used for exfiltration"

  # ── Prompt: Destructive Operations ──────────────────
  - name: approve-file-delete
    tool: "*delete*|*remove*|*unlink*"
    action: prompt
    message: "File deletion requires approval"

  - name: approve-shell-exec
    tool: "shell_exec|run_command|execute_command|bash"
    action: prompt
    message: "Shell command execution requires approval"

  # ── Allow: Safe Read Operations ─────────────────────
  - name: allow-read-file
    tool: "read_file|get_file_contents|view_file"
    action: allow

  - name: allow-list-dir
    tool: "list_directory|list_dir|ls"
    action: allow

  - name: allow-search
    tool: "search_files|grep|find_files|ripgrep"
    action: allow
```

## Security Modules

The default policy also enables these security modules (configured under `security:`):

```yaml
security:
  injectionDetection:
    enabled: true
    sensitivity: medium     # Detects 30+ injection patterns
  egressControl:
    enabled: true
    blockPrivateIPs: true   # RFC1918, loopback, link-local
    blockMetadataEndpoints: true  # AWS/GCP/Azure metadata SSRF
  killSwitch:
    enabled: true
    checkFile: true         # Emergency deny-all via .agent-wall-kill file
  chainDetection:
    enabled: true           # Detects exfiltration chains (read→curl, etc.)
  signing: false            # HMAC-SHA256 audit log signing
```

## Philosophy

The default policy follows the **principle of least privilege**:

1. **Explicitly deny** known dangerous patterns (credential access, exfiltration vectors)
2. **Require approval** for destructive operations (shell, delete) and scripting one-liners
3. **Allow** known safe operations (read, list, search)
4. **Prompt** for everything else (via `defaultAction: prompt`)
5. **Scan responses** for leaked secrets, tokens, and private keys
6. **Block** responses containing private keys outright
7. **Detect and block** prompt injection attacks in tool arguments
8. **Block** SSRF attempts to private IPs and cloud metadata endpoints
9. **Detect** suspicious tool call chains (multi-step attacks)

## Customizing

Generate a config file based on these defaults:

```bash
agent-wall init
```

Then edit `agent-wall.yaml` to match your needs.
