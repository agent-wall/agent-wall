/**
 * Agent Wall JSON-RPC Types
 *
 * Mirrors the MCP protocol's JSON-RPC 2.0 message format.
 * We define our own types instead of depending on the MCP SDK
 * so Agent Wall has zero coupling to any specific MCP version.
 */

import { z } from "zod";

// ── JSON-RPC 2.0 Base ──────────────────────────────────────────────

export const JsonRpcRequestSchema = z.object({
  jsonrpc: z.literal("2.0"),
  id: z.union([z.string(), z.number()]),
  method: z.string(),
  params: z.record(z.unknown()).optional(),
});

export const JsonRpcNotificationSchema = z.object({
  jsonrpc: z.literal("2.0"),
  method: z.string(),
  params: z.record(z.unknown()).optional(),
});

export const JsonRpcResponseSchema = z.object({
  jsonrpc: z.literal("2.0"),
  id: z.union([z.string(), z.number()]),
  result: z.unknown().optional(),
  error: z
    .object({
      code: z.number(),
      message: z.string(),
      data: z.unknown().optional(),
    })
    .optional(),
});

export const JsonRpcMessageSchema = z.union([
  JsonRpcRequestSchema,
  JsonRpcNotificationSchema,
  JsonRpcResponseSchema,
]);

export type JsonRpcRequest = z.infer<typeof JsonRpcRequestSchema>;
export type JsonRpcNotification = z.infer<typeof JsonRpcNotificationSchema>;
export type JsonRpcResponse = z.infer<typeof JsonRpcResponseSchema>;
export type JsonRpcMessage = z.infer<typeof JsonRpcMessageSchema>;

// ── MCP-specific message types ──────────────────────────────────────

/** MCP tools/call request params */
export interface ToolCallParams {
  name: string;
  arguments?: Record<string, unknown>;
}

/** MCP tools/list result */
export interface ToolListResult {
  tools: Array<{
    name: string;
    description?: string;
    inputSchema?: Record<string, unknown>;
    annotations?: Record<string, unknown>;
  }>;
  nextCursor?: string;
}

/** MCP response content block (text, image, resource) */
export interface McpContentBlock {
  type: string;
  text?: string;
  data?: string;
  mimeType?: string;
  [key: string]: unknown;
}

// ── Helpers ─────────────────────────────────────────────────────────

export function isRequest(msg: JsonRpcMessage): msg is JsonRpcRequest {
  return "id" in msg && "method" in msg;
}

export function isNotification(
  msg: JsonRpcMessage
): msg is JsonRpcNotification {
  return !("id" in msg) && "method" in msg;
}

export function isResponse(msg: JsonRpcMessage): msg is JsonRpcResponse {
  return "id" in msg && !("method" in msg);
}

export function isToolCall(msg: JsonRpcMessage): boolean {
  return isRequest(msg) && msg.method === "tools/call";
}

export function isToolList(msg: JsonRpcMessage): boolean {
  return isRequest(msg) && msg.method === "tools/list";
}

export function getToolCallParams(
  msg: JsonRpcRequest
): ToolCallParams | null {
  if (msg.method !== "tools/call" || !msg.params) return null;
  const params = msg.params as Record<string, unknown>;
  if (typeof params.name !== "string") return null;
  return {
    name: params.name,
    arguments: (params.arguments as Record<string, unknown>) ?? {},
  };
}

/**
 * Create a JSON-RPC error response for a denied tool call.
 */
export function createDenyResponse(
  id: string | number,
  message: string
): JsonRpcResponse {
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code: -32001, // Custom: policy denied
      message: `Agent Wall: ${message}`,
    },
  };
}

/**
 * Create a JSON-RPC error response for a tool call requiring approval.
 */
export function createPromptResponse(
  id: string | number,
  message: string
): JsonRpcResponse {
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code: -32002, // Custom: awaiting approval
      message: `Agent Wall: Awaiting approval — ${message}`,
    },
  };
}
