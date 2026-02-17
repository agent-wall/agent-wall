# How It Works

Agent Wall acts as a **two-way transparent proxy** between your MCP client and MCP server — inspecting tool calls going in and responses coming out.

## Architecture

```
┌─────────────┐     stdin/stdout     ┌──────────────┐     stdin/stdout     ┌────────────┐
│  MCP Client │ ◄──────────────────► │  Agent Wall  │ ◄──────────────────► │ MCP Server │
│  (any)      │                      │    Proxy     │                      │  (any)     │
└─────────────┘                      └──────┬───────┘                      └────────────┘
                                    │
                            ┌───────▼───────┐
                            │ agent-wall.yaml│
                            │  Policy Rules  │
                            │  + Response    │
                            │    Scanning    │
                            └────────────────┘
```

## Message Flow

### Inbound Security Pipeline (Client → Server)

Every `tools/call` request runs through a **5-step defense-in-depth pipeline** before reaching the MCP server:

1. **Kill Switch** — If the emergency kill switch is active (file or signal), deny ALL calls immediately
2. **Injection Detection** — Scan all arguments for prompt injection attacks (30+ patterns covering instruction overrides, system markers, authority claims, exfiltration commands, unicode obfuscation, encoded injections)
3. **Egress Control** — Check arguments for blocked URLs/IPs (private IPs, cloud metadata endpoints, SSRF vectors including hex/octal IP obfuscation)
4. **Policy Engine** — Evaluate the tool call against YAML-defined rules (first-match-wins, glob patterns, rate limiting, strict/zero-trust mode)
5. **Chain Detection** — Record the call and check for suspicious multi-step attack patterns (read→exfil, write→execute, directory scanning bursts)

After all checks pass, the action is executed:
- **allow** → Forward the message to the MCP server (and track for response scanning)
- **deny** → Return an error response to the client (server never sees it)
- **prompt** → Ask the human operator for approval via terminal

All other messages (initialize, tools/list, notifications) are **passed through** untouched.

### Outbound (Server → Client)

6. **Server → Agent Wall**: Responses from the MCP server are intercepted
7. **Response Classification**:
   - Responses to tracked `tools/call` requests → **scanned** by the response scanner
   - All other responses → **passed through** untouched
8. **Response Scanning**: For tool call responses, the scanner:
   - Runs 14+ built-in patterns (API keys, tokens, private keys, passwords, database URLs)
   - Runs custom user-defined patterns from the YAML config
   - Checks response size against configured limits
9. **Response Action**:
   - **pass** → Forward response to client as-is (clean or informational findings)
   - **redact** → Replace matched content with `[REDACTED]` then forward
   - **block** → Return an error response to the client (sensitive content never reaches the LLM)

## JSON-RPC Protocol

Agent Wall works at the MCP protocol level. MCP uses [JSON-RPC 2.0](https://www.jsonrpc.org/specification) over stdio, with messages separated by newlines.

A tool call looks like:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "read_file",
    "arguments": {
      "path": "/home/user/.ssh/id_rsa"
    }
  }
}
```

When Agent Wall denies this call, the client receives:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32001,
    "message": "Agent Wall: Access to SSH keys is blocked by default policy"
  }
}
```

Agent Wall uses custom JSON-RPC error codes: `-32001` for policy denials and `-32002` for prompt-pending responses.

## Works With Any MCP Server

Agent Wall operates at the **MCP protocol level** (JSON-RPC 2.0 over stdio), not at the application level. This means it works with **every MCP server** — no matter who wrote it, what it does, or what tools it exposes.

- Official MCP servers (filesystem, GitHub, Playwright, Slack, etc.)
- Third-party servers (Supabase, Stripe, Snowflake, etc.)
- Your own custom MCP servers
- Any future MCP server that speaks the standard protocol

You never need to modify Agent Wall's code to support a new MCP server. Just wrap it:

```bash
agent-wall wrap -- <any-mcp-server-command>
```

The **scan** command's risk detection is a convenience feature that recognizes popular server names (48 patterns), but the **wrap** and **policy engine** work universally with all servers.

## Works With Any MCP Client

Agent Wall is also client-agnostic. Any MCP client that spawns servers via stdio can use Agent Wall:

- Claude Code, Claude Desktop
- VS Code / GitHub Copilot (MCP support since v1.99)
- Cursor
- Windsurf (Codeium)
- Cline, Continue.dev
- Any custom MCP client

The integration is always the same: replace the server command with `agent-wall wrap -- <original-command>`.

## Real-Time Dashboard

Agent Wall can serve a browser-based security dashboard directly from the proxy process:

```bash
agent-wall wrap --dashboard -- npx mcp-server
# → Dashboard at http://localhost:61100
```

The dashboard connects via WebSocket to the same port and receives:
- **Live events** — Every tool call, denial, injection, and SSRF attempt
- **Stats** — Updated every 2 seconds
- **Audit entries** — Structured log entries with rule names and verdicts
- **Kill switch** — Remote emergency toggle from the browser

See [Real-Time Dashboard](/guide/dashboard) for details.

## Key Design Decisions

### Zero MCP SDK dependency
Agent Wall implements its own JSON-RPC stream parser (`ReadBuffer`), so it works with any MCP version without dependency conflicts.

### First-match-wins
Policy rules are evaluated in order — the first rule that matches a tool call determines the action. This makes policies predictable and easy to reason about.

### Stdio transparency
For everything except `tools/call` requests and their responses, Agent Wall is completely invisible. The MCP client and server communicate as if Agent Wall isn't there.
