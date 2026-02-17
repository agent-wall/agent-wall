# Real-Time Dashboard

Agent Wall includes a browser-based security dashboard that streams proxy events live via WebSocket. Monitor tool calls, attacks, and response scans in real time.

## Quick Start

```bash
agent-wall wrap --dashboard -- npx @modelcontextprotocol/server-filesystem /home/user
```

Open `http://localhost:61100` in your browser. The dashboard connects automatically and starts streaming events.

## Custom Port

```bash
agent-wall wrap --dashboard --dashboard-port 8080 -- npx mcp-server
```

## What You See

The dashboard is a dark-themed single-page app with six panels:

### Stats Cards

Five real-time metrics across the top:

| Card | Description |
|------|-------------|
| **Total Calls** | Total tool calls intercepted |
| **Forwarded** | Calls allowed through (green) |
| **Denied** | Calls blocked by policy (red) |
| **Attacks Blocked** | Injection, SSRF, chain attacks caught (orange) |
| **Scanned** | Responses scanned for secrets (blue) |

### Event Feed

Live scrolling list of every proxy event — color-coded by action (green = allow, red = deny, yellow = prompt). Filter by action type using the chips at the top. Auto-scrolls to new events, pausable.

### Attack Panel

Groups detected attacks by category:

- **Injections** — Prompt injection attempts (role overrides, system markers, etc.)
- **Egress / SSRF** — Blocked URLs, private IP access, metadata endpoint probes
- **Chain Attacks** — Suspicious multi-step sequences (read → exfil, write → execute)
- **Response Threats** — Secrets or PII detected in server responses
- **Kill Switch** — Emergency deny-all activations

Each category is collapsible with a count badge.

### Rule Table

Sortable table showing which policy rules have been triggered and how many times. Click column headers to sort by name, action, or hit count.

### Kill Switch Toggle

Red emergency button in the header. When activated, Agent Wall denies ALL tool calls immediately. Requires confirmation before activation. Deactivation is immediate.

### Audit Search

Search and filter the audit log by text query and action type (allow/deny/prompt). Loads entries on demand from the server.

## Architecture

```
agent-wall wrap --dashboard -- npx mcp-server
                    │
     ┌──────────────┴──────────────┐
     │  DashboardServer            │
     │  HTTP: serves React SPA     │
     │  WS: streams proxy events   │
     │  Port: 61100 (configurable) │
     └──────────────┬──────────────┘
                    │ WebSocket
     ┌──────────────┴──────────────┐
     │  Browser Dashboard          │
     │  Auto-reconnect (2s)        │
     │  Event cap: 500 items       │
     └─────────────────────────────┘
```

The dashboard runs on the **same process** as the proxy — no separate server to manage. It serves a pre-built React SPA over HTTP and pushes events via WebSocket on the same port.

## Integration Examples

### Claude Code with Dashboard

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agent-wall",
      "args": ["wrap", "--dashboard", "--", "npx", "@modelcontextprotocol/server-filesystem", "/home/user"]
    }
  }
}
```

### With Audit Logging

```bash
agent-wall wrap --dashboard --log-file ./audit.log -- npx mcp-server
```

The dashboard receives the same structured audit entries written to the log file, streaming them live to the browser.

## Programmatic Usage

```typescript
import { DashboardServer, StdioProxy, PolicyEngine, KillSwitch } from "@agent-wall/core";

const dashboard = new DashboardServer({
  port: 61100,
  proxy,           // StdioProxy instance
  killSwitch,      // KillSwitch instance (optional)
  policyEngine,    // PolicyEngine instance (optional)
  logger,          // AuditLogger instance (optional)
  staticDir,       // Path to built React app (optional)
  statsIntervalMs: 2000, // How often to push stats (default: 2000)
});

await dashboard.start();

// Wire audit entries
logger.setOnEntry((entry) => {
  dashboard.handleAuditEntry(entry);
});
```

## WebSocket Protocol

The dashboard communicates over a standard WebSocket connection. Messages are JSON with this structure:

```typescript
interface WsMessage {
  type: "event" | "stats" | "audit" | "killSwitch" | "ruleHits" | "config" | "welcome";
  ts: string;     // ISO timestamp
  payload: any;
}
```

### Server → Client Messages

| Type | Payload | When |
|------|---------|------|
| `welcome` | `{ message }` | On connection |
| `stats` | `{ total, forwarded, denied, ... }` | Every 2s |
| `event` | `{ event, tool, detail, severity }` | On proxy event |
| `audit` | `{ tool, verdict, ... }` | On audit entry |
| `killSwitch` | `{ active }` | On toggle |
| `ruleHits` | `{ [ruleName]: count }` | Periodically |
| `config` | `{ defaultAction, rules, mode }` | On connection |

### Client → Server Messages

| Type | Description |
|------|-------------|
| `toggleKillSwitch` | Toggle the emergency kill switch |
| `getStats` | Request current stats |
| `getConfig` | Request current policy config |
| `getAuditLog` | Query audit log with filters |

## Notes

- The dashboard uses **no external UI framework** — plain React with CSS variables
- Events are capped at **500 items** in the browser to prevent memory bloat
- WebSocket auto-reconnects after **2 seconds** on disconnect
- If the dashboard package isn't built, a **fallback HTML page** is served with connection instructions
- The dashboard has **zero impact** on proxy performance — events are broadcast asynchronously
