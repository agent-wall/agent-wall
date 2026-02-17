# @agent-wall/core

The core library for Agent Wall. Use this to integrate Agent Wall programmatically into your own tools.

## Installation

```bash
npm install @agent-wall/core
```

## Quick Example

```typescript
import {
  PolicyEngine,
  AuditLogger,
  StdioProxy,
  ResponseScanner,
  loadPolicy,
  createTerminalPromptHandler,
} from "@agent-wall/core";

// Load policy
const { config } = loadPolicy();

// Create engine
const engine = new PolicyEngine(config);

// Create response scanner from config
const scanner = config.responseScanning?.enabled !== false
  ? new ResponseScanner(config.responseScanning)
  : undefined;

// Create proxy
const proxy = new StdioProxy({
  command: "npx",
  args: ["@modelcontextprotocol/server-filesystem", "/home/user"],
  policyEngine: engine,
  responseScanner: scanner,
  logger: new AuditLogger({ stdout: true, redact: true }),
  onPrompt: createTerminalPromptHandler(),
});

await proxy.start();
```

## Exports

### Classes

| Export | Description |
|--------|-------------|
| [`PolicyEngine`](/api/policy-engine) | Evaluates tool calls against policy rules |
| [`StdioProxy`](/api/stdio-proxy) | Transparent two-way stdio proxy for MCP servers |
| [`AuditLogger`](/api/audit-logger) | Structured JSON audit logger |
| [`ResponseScanner`](/api/response-scanner) | Scans server responses for secrets, PII, and oversize content |
| [`DashboardServer`](/api/dashboard-server) | WebSocket + HTTP server for real-time browser dashboard |
| `ReadBuffer` | Newline-delimited JSON-RPC stream parser |
| `InjectionDetector` | Prompt injection detection (30+ patterns) |
| `EgressControl` | URL/SSRF protection with IP blocking |
| `KillSwitch` | Emergency deny-all (file, signal, programmatic) |
| `ChainDetector` | Tool call sequence analysis |

### Functions

| Export | Description |
|--------|-------------|
| `loadPolicy(path?)` | Load and validate a YAML policy config |
| `loadPolicyFile(path)` | Load a specific config file |
| `parsePolicyYaml(yaml)` | Parse YAML string to config |
| `discoverPolicyFile()` | Auto-discover config file |
| `getDefaultPolicy()` | Get the built-in default policy |
| `generateDefaultConfigYaml()` | Generate default YAML config string |
| `createTerminalPromptHandler()` | Create a terminal-based approval prompt |
| `createDefaultScanner()` | Create a response scanner with sensible defaults |
| `serializeMessage(msg)` | Serialize a JSON-RPC message |
| `deserializeMessage(str)` | Parse a JSON-RPC message |

### Type Guards

| Export | Description |
|--------|-------------|
| `isRequest(msg)` | Check if message is a JSON-RPC request |
| `isResponse(msg)` | Check if message is a JSON-RPC response |
| `isNotification(msg)` | Check if message is a notification |
| `isToolCall(msg)` | Check if message is a `tools/call` request |
| `isToolList(msg)` | Check if message is a `tools/list` response |
| `getToolCallParams(msg)` | Extract tool name and arguments |
| `createDenyResponse(id, message)` | Create a deny error response (code: -32001) |
| `createPromptResponse(id, message)` | Create a prompt-pending response (code: -32002) |
