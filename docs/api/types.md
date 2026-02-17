# Types

Core TypeScript types and JSON-RPC utilities.

## JSON-RPC Types

```typescript
interface JsonRpcMessage {
  jsonrpc: "2.0";
}

interface JsonRpcRequest extends JsonRpcMessage {
  id: string | number;
  method: string;
  params?: unknown;
}

interface JsonRpcResponse extends JsonRpcMessage {
  id: string | number;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

interface JsonRpcNotification extends JsonRpcMessage {
  method: string;
  params?: unknown;
}
```

## Tool Call Types

```typescript
interface ToolCallParams {
  name: string;
  arguments?: Record<string, unknown>;
}

interface ToolListResult {
  tools: Array<{
    name: string;
    description?: string;
    inputSchema?: Record<string, unknown>;
  }>;
}
```

## Type Guards

```typescript
// Check message types
isRequest(msg: JsonRpcMessage): msg is JsonRpcRequest
isResponse(msg: JsonRpcMessage): msg is JsonRpcResponse
isNotification(msg: JsonRpcMessage): msg is JsonRpcNotification

// MCP-specific checks
isToolCall(msg: JsonRpcMessage): boolean   // method === "tools/call"
isToolList(msg: JsonRpcMessage): boolean   // method === "tools/list"

// Extract tool call details
getToolCallParams(msg: JsonRpcRequest): ToolCallParams | null
```

## Response Factories

```typescript
// Create a deny error response (code: -32001)
createDenyResponse(
  id: string | number,
  message: string
): JsonRpcResponse

// Create a prompt-pending error response (code: -32002)
createPromptResponse(
  id: string | number,
  message: string
): JsonRpcResponse
```

## Zod Schemas

All types have corresponding [Zod](https://zod.dev) schemas for runtime validation:

```typescript
import {
  JsonRpcMessageSchema,
  JsonRpcRequestSchema,
  JsonRpcResponseSchema,
  JsonRpcNotificationSchema,
} from "@agent-wall/core";

// Validate a parsed JSON object
const result = JsonRpcRequestSchema.safeParse(parsed);
if (result.success) {
  // result.data is typed as JsonRpcRequest
}
```
