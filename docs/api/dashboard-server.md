# DashboardServer

WebSocket + HTTP server that bridges proxy events to a browser dashboard. Serves a React SPA over HTTP and streams events via WebSocket on the same port.

## Constructor

```typescript
import { DashboardServer } from "@agent-wall/core";

const server = new DashboardServer(options);
```

### `DashboardServerOptions`

```typescript
interface DashboardServerOptions {
  port: number;                    // Port to listen on (use 0 for random)
  proxy: StdioProxy;               // Proxy instance to subscribe to events
  killSwitch?: KillSwitch;         // Kill switch instance for remote toggle
  policyEngine?: PolicyEngine;     // Policy engine for config reporting
  logger?: AuditLogger;            // Audit logger for log queries
  staticDir?: string;              // Path to built React app directory
  statsIntervalMs?: number;        // Stats broadcast interval (default: 2000)
}
```

## Methods

### `start()`

Start the HTTP + WebSocket server.

```typescript
await server.start();
```

### `stop()`

Gracefully shut down the server and close all WebSocket connections.

```typescript
await server.stop();
```

### `getPort()`

Get the actual listening port (useful when using port `0` for random assignment).

```typescript
const port = server.getPort();
// → 61100
```

### `handleAuditEntry(entry)`

Push a structured audit entry to all connected dashboard clients and track rule hits.

```typescript
server.handleAuditEntry({
  timestamp: new Date().toISOString(),
  sessionId: "abc-123",
  direction: "request",
  method: "tools/call",
  tool: "read_file",
  verdict: {
    action: "deny",
    rule: "block-ssh-keys",
    message: "SSH key access blocked",
  },
});
```

## WebSocket Messages

### Server → Client

```typescript
type WsMessageType = "event" | "stats" | "audit" | "killSwitch" | "ruleHits" | "config" | "welcome";

interface WsMessage<T = unknown> {
  type: WsMessageType;
  ts: string;       // ISO timestamp
  payload: T;
}
```

#### `stats` payload

```typescript
interface StatsPayload {
  forwarded: number;
  denied: number;
  prompted: number;
  total: number;
  scanned: number;
  responseBlocked: number;
  responseRedacted: number;
  uptime: number;           // Seconds since server start
  killSwitchActive: boolean;
}
```

#### `event` payload

```typescript
interface ProxyEventPayload {
  event: string;     // "allowed", "denied", "injectionDetected", etc.
  tool?: string;     // Tool name
  detail?: string;   // Description
  severity: "info" | "warn" | "critical";
}
```

#### `ruleHits` payload

```typescript
interface RuleHitsPayload {
  [ruleName: string]: number;  // Rule name → hit count
}
```

#### `config` payload

```typescript
interface ConfigPayload {
  defaultAction?: string;
  ruleCount?: number;
  mode?: string;
  modules: {
    injection: boolean;
    egress: boolean;
    killSwitch: boolean;
    chain: boolean;
    responseScanning: boolean;
  };
}
```

### Client → Server

```typescript
type ClientWsMessage =
  | { type: "toggleKillSwitch" }
  | { type: "getStats" }
  | { type: "getConfig" }
  | { type: "getAuditLog"; filter?: string; search?: string; last?: number };
```

## Example

```typescript
import {
  DashboardServer,
  StdioProxy,
  PolicyEngine,
  AuditLogger,
  KillSwitch,
  loadPolicy,
} from "@agent-wall/core";

const { config } = loadPolicy();
const engine = new PolicyEngine(config);
const killSwitch = new KillSwitch({ enabled: true });
const logger = new AuditLogger({ stdout: true });

const proxy = new StdioProxy({
  command: "npx",
  args: ["@modelcontextprotocol/server-filesystem", "/tmp"],
  policyEngine: engine,
});

const dashboard = new DashboardServer({
  port: 61100,
  proxy,
  killSwitch,
  policyEngine: engine,
  logger,
});

// Wire audit entries to dashboard
logger.setOnEntry((entry) => {
  dashboard.handleAuditEntry(entry);
});

await dashboard.start();
await proxy.start();
```
