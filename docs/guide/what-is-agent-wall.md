# What is Agent Wall?

Agent Wall is a **two-way security firewall for AI agents**. It intercepts MCP (Model Context Protocol) tool calls going **in** and scans server responses coming **out**, enforcing YAML-based policies and blocking dangerous operations before they happen.

## The Problem

AI agents can now execute tools — read files, run shell commands, query databases, make HTTP requests. Without guardrails, a single prompt injection can:

1. **Read** your SSH keys, `.env` files, credentials
2. **Exfiltrate** data via `curl`, `wget`, or DNS tunneling
3. **Execute** arbitrary shell commands with your permissions
4. **Leak** secrets in tool responses — API keys, tokens, private keys flow right back to the LLM

## The Solution

Agent Wall sits between the MCP client (Claude Code, Cursor, etc.) and the MCP server, enforcing a YAML policy on every tool call:

```
MCP Client  ←→  Agent Wall Proxy  ←→  MCP Server
                      ↕
               agent-wall.yaml
           (rules + responseScanning)
```

Think of it as **Cloudflare for AI agents** — transparent, zero-config, and powerful.

## Key Features

- **Two-way firewall** — Inspects tool calls going in AND responses coming out
- **Policy enforcement** — YAML-based rules with glob matching and argument inspection
- **Response scanning** — Detects leaked API keys, tokens, private keys, PII in server responses
- **Three request actions** — `allow`, `deny`, `prompt` (ask human for approval)
- **Three response actions** — `pass`, `redact`, `block`
- **Zero config** — Sensible built-in defaults that protect immediately
- **Transparent proxy** — No SDK changes, no code modifications needed
- **Audit logging** — Structured JSON logs with sensitive value redaction
- **Rate limiting** — Global and per-rule limits
- **Security scanning** — Find unprotected MCP servers in your config

## How is it different?

Unlike traditional API gateways, Agent Wall:

- Works at the **MCP protocol level** (JSON-RPC over stdio)
- Understands **tool semantics** — not just HTTP verbs
- Scans **both directions** — requests AND responses
- Provides **human-in-the-loop approval** for dangerous operations
- **Redacts secrets** from responses before the LLM sees them
- Requires **zero changes** to your MCP servers
- Is designed specifically for **AI agent security**

## Works with any MCP server

Agent Wall is **protocol-level**, not application-level. It works with every MCP server that uses stdio transport — official servers, third-party servers, or your own custom ones. There are 1000+ MCP servers in the ecosystem and growing; Agent Wall protects them all without any code changes.

```bash
# Official servers
agent-wall wrap -- npx @modelcontextprotocol/server-filesystem /path
agent-wall wrap -- npx @modelcontextprotocol/server-github

# Third-party servers
agent-wall wrap -- npx @supabase/mcp-server-supabase
agent-wall wrap -- npx @stripe/mcp-server-stripe

# Your own servers
agent-wall wrap -- node my-custom-mcp-server.js
agent-wall wrap -- python my_mcp_server.py
```

## Works with any MCP client

Any MCP client that spawns servers via stdio can use Agent Wall:

- **Claude Code** / **Claude Desktop**
- **VS Code / GitHub Copilot** (MCP support since v1.99)
- **Cursor**
- **Windsurf** (Codeium)
- **Cline**, **Continue.dev**
- Any custom MCP client
