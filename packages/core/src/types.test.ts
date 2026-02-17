/**
 * Tests for types module — JSON-RPC message helpers.
 */

import { describe, it, expect } from "vitest";
import {
  isRequest,
  isResponse,
  isNotification,
  isToolCall,
  isToolList,
  getToolCallParams,
  createDenyResponse,
  createPromptResponse,
  type JsonRpcMessage,
  type JsonRpcRequest,
} from "./types.js";

describe("message type guards", () => {
  const request: JsonRpcMessage = {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name: "read_file", arguments: { path: "/test" } },
  };

  const response: JsonRpcMessage = {
    jsonrpc: "2.0",
    id: 1,
    result: { content: [{ type: "text", text: "hello" }] },
  };

  const notification: JsonRpcMessage = {
    jsonrpc: "2.0",
    method: "notifications/initialized",
  };

  it("isRequest should identify requests", () => {
    expect(isRequest(request)).toBe(true);
    expect(isRequest(response)).toBe(false);
    expect(isRequest(notification)).toBe(false);
  });

  it("isResponse should identify responses", () => {
    expect(isResponse(response)).toBe(true);
    expect(isResponse(request)).toBe(false);
    expect(isResponse(notification)).toBe(false);
  });

  it("isNotification should identify notifications", () => {
    expect(isNotification(notification)).toBe(true);
    expect(isNotification(request)).toBe(false);
    expect(isNotification(response)).toBe(false);
  });

  it("isToolCall should identify tools/call requests", () => {
    expect(isToolCall(request)).toBe(true);
    expect(
      isToolCall({ jsonrpc: "2.0", id: 1, method: "tools/list" })
    ).toBe(false);
    expect(isToolCall(response)).toBe(false);
  });

  it("isToolList should identify tools/list requests", () => {
    expect(
      isToolList({ jsonrpc: "2.0", id: 1, method: "tools/list" })
    ).toBe(true);
    expect(isToolList(request)).toBe(false);
  });
});

describe("getToolCallParams", () => {
  it("should extract tool name and arguments", () => {
    const req: JsonRpcRequest = {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "read_file", arguments: { path: "/test" } },
    };

    const result = getToolCallParams(req);
    expect(result).toEqual({
      name: "read_file",
      arguments: { path: "/test" },
    });
  });

  it("should return null for non-tools/call methods", () => {
    const req: JsonRpcRequest = {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
    };

    expect(getToolCallParams(req)).toBeNull();
  });

  it("should return null when params missing", () => {
    const req: JsonRpcRequest = {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
    };

    expect(getToolCallParams(req)).toBeNull();
  });

  it("should default arguments to empty object", () => {
    const req: JsonRpcRequest = {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "some_tool" },
    };

    const result = getToolCallParams(req);
    expect(result).toEqual({ name: "some_tool", arguments: {} });
  });
});

describe("createDenyResponse", () => {
  it("should create a JSON-RPC error with custom code and message", () => {
    const resp = createDenyResponse(42, "Access denied");
    expect(resp).toEqual({
      jsonrpc: "2.0",
      id: 42,
      error: {
        code: -32001,
        message: "Agent Wall: Access denied",
      },
    });
  });

  it("should work with string IDs", () => {
    const resp = createDenyResponse("req-abc", "Blocked");
    expect(resp.id).toBe("req-abc");
  });
});

describe("createPromptResponse", () => {
  it("should create a prompt-awaiting error response", () => {
    const resp = createPromptResponse(7, "Requires approval");
    expect(resp).toEqual({
      jsonrpc: "2.0",
      id: 7,
      error: {
        code: -32002,
        message: "Agent Wall: Awaiting approval — Requires approval",
      },
    });
  });
});
