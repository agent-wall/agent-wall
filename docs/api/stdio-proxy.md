# StdioProxy

The transparent two-way proxy that sits between the MCP client and server. This is the core of Agent Wall — it inspects tool calls going in and scans responses coming out.

## Constructor

```typescript
const proxy = new StdioProxy(options: ProxyOptions);
```

### `ProxyOptions`

```typescript
interface ProxyOptions {
  command: string;               // Server command to spawn
  args: string[];                // Server command arguments
  policyEngine: PolicyEngine;    // Policy evaluation engine
  responseScanner?: ResponseScanner;  // Response scanner (optional)
  logger?: AuditLogger;          // Audit logger instance
  onPrompt?: PromptHandler;      // Handler for "prompt" actions
  onReady?: () => void;          // Called when server is ready
  onExit?: (code: number | null) => void;  // Called on server exit
  onError?: (error: Error) => void;        // Called on errors
}
```

## Methods

### `start()`

Start the proxy — spawns the MCP server and begins intercepting messages.

```typescript
await proxy.start();
```

### `stop()`

Gracefully stop the proxy and kill the child process.

```typescript
proxy.stop();
```

### `getStats()`

Get session statistics.

```typescript
const stats = proxy.getStats();
// { total: 42, forwarded: 35, denied: 5, prompted: 2, scanned: 35, responseBlocked: 1, responseRedacted: 3 }
```

## Example

```typescript
import {
  StdioProxy,
  PolicyEngine,
  AuditLogger,
  loadPolicy,
  createTerminalPromptHandler,
} from "@agent-wall/core";

const { config } = loadPolicy();
const engine = new PolicyEngine(config);
const logger = new AuditLogger({ stdout: true, redact: true });

const proxy = new StdioProxy({
  command: "npx",
  args: ["@modelcontextprotocol/server-filesystem", "/home/user"],
  policyEngine: engine,
  logger,
  onPrompt: createTerminalPromptHandler(),
  onReady: () => console.error("Server started"),
  onExit: (code) => {
    const stats = proxy.getStats();
    console.error(`Session ended. ${stats.total} calls processed.`);
    process.exit(code ?? 0);
  },
});

// Handle shutdown
process.on("SIGINT", () => proxy.stop());
process.on("SIGTERM", () => proxy.stop());

await proxy.start();
```

## Prompt Handler

The `onPrompt` callback is called when a tool call matches a `prompt` rule. It receives the tool call details and must return a boolean (approve/deny).

```typescript
type PromptHandler = (toolName: string, args: Record<string, unknown>) => Promise<boolean>;
```

Use `createTerminalPromptHandler()` for the built-in terminal prompt, or implement your own.
