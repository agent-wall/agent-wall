# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-02-17

### Added

- **Two-Way Firewall Architecture**
  - **Inbound**: 5-step defense-in-depth pipeline controls tool calls before they reach the server
  - **Outbound**: Response Scanner inspects tool results before they reach the LLM

- **Inbound Security Pipeline** — every `tools/call` runs through:
  1. **Kill Switch** — Emergency deny-all (file-based, signal-based, programmatic)
  2. **Injection Detection** — 30+ patterns detect prompt injection attacks (role overrides, system markers, authority claims, exfiltration commands, unicode obfuscation, encoded injections). Configurable sensitivity levels (low/medium/high)
  3. **Egress Control / SSRF Protection** — Block private IPs (RFC1918), cloud metadata endpoints, hex/octal IP obfuscation. Configurable allowlists and blocklists
  4. **Policy Engine** — YAML-based first-match-wins rule evaluation with glob patterns, pipe-separated alternatives, argument matching, per-rule and global rate limiting, strict/zero-trust mode
  5. **Chain Detection** — Suspicious multi-step pattern detection (read→exfil, write→execute, directory scanning bursts)

- **Response Scanner** — Intercept and sanitize MCP server responses
  - 14 built-in secret patterns (AWS keys, GitHub tokens, JWTs, private keys, DB URLs, etc.)
  - 5 PII patterns (email, phone, SSN, credit card, IP) — opt-in
  - Custom user-defined regex patterns via YAML config
  - Three response actions: `pass`, `redact`, `block`
  - Response size limits with configurable oversize action
  - Automatic `[REDACTED:pattern-name]` replacement
  - ReDoS-safe pattern validation

- **Stdio Proxy** — Transparent MCP protocol interception
  - JSON-RPC 2.0 stream parsing with buffer overflow protection (10MB default)
  - Pending call TTL (30s) prevents memory leaks from orphaned requests
  - Human-in-the-loop terminal prompt for `prompt` action
  - Graceful lifecycle management
  - Works with **any** MCP server (protocol-level, no SDK dependency)

- **Audit Logger** — Structured JSON logging
  - HMAC-SHA256 chain signing (tamper-evident log entries)
  - Log rotation (max file size with automatic rotation)
  - Sensitive value redaction
  - File and console output

- **Security Hardening**
  - Path traversal normalization (`posix.normalize` before matching)
  - Unicode NFC normalization (prevents homoglyph bypass)
  - Safe YAML loading (JSON_SCHEMA mode, no code execution)
  - Secure session IDs (`crypto.randomUUID()`)

- **Real-Time Dashboard**
  - Browser-based dark-themed React SPA served from the proxy process
  - 5 real-time stats cards (total, forwarded, denied, attacks, scanned)
  - Live event feed with filtering and auto-scroll
  - Attack panel grouped by category (injections, SSRF, chains, response threats)
  - Sortable rule hit table
  - Kill switch toggle with confirmation
  - Audit log search with text and action filters
  - WebSocket + HTTP server (`DashboardServer`) with stats broadcast, kill switch remote toggle, policy config reporting
  - `--dashboard` and `--dashboard-port <port>` CLI flags

- **CLI Commands**
  - `agent-wall wrap` — Wrap MCP servers with policy enforcement (dashboard, audit logging, hot-reload, dry-run)
  - `agent-wall init` — Generate starter configuration
  - `agent-wall test` — Dry-run tool calls against policy
  - `agent-wall audit` — View and filter audit logs
  - `agent-wall scan` — Scan MCP configs for security risks (48 known risk patterns)
  - `agent-wall validate` — Validate policy configuration
  - `agent-wall doctor` — Health check for config, environment, and MCP setup

- **MCP Client Detection** — Auto-discovers configs for:
  - Claude Code, Claude Desktop (macOS/Windows/Linux)
  - Cursor
  - VS Code / GitHub Copilot
  - Windsurf (Codeium)
  - Cline, Continue.dev

- **Policy Hot-Reload** — Watches `agent-wall.yaml` for changes and automatically reloads the policy without restarting the proxy

- **Environment Variables**
  - `AGENT_WALL_CONFIG` — Default config file path
  - `AGENT_WALL_LOG` — Default audit log file path

- **Scan JSON Output** — `--json` flag for CI/CD integration

- **Built-in Default Policy** — Sensible zero-config protection
  - Block credential and key access (`.ssh/`, `.env`, `.pem`, `.key`)
  - Block exfiltration vectors (`curl`, `wget`, `netcat`, `powershell`, DNS tunneling)
  - Prompt for destructive operations (shell exec, file deletion)
  - Allow safe read operations
  - 200 calls/minute global rate limit
