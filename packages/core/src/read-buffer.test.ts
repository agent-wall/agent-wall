/**
 * Tests for ReadBuffer — JSON-RPC message parsing over newline-delimited streams.
 */

import { describe, it, expect } from "vitest";
import { ReadBuffer, serializeMessage, deserializeMessage } from "./read-buffer.js";
import type { JsonRpcMessage } from "./types.js";

describe("ReadBuffer", () => {
  it("should parse a single complete message", () => {
    const buf = new ReadBuffer();
    const msg: JsonRpcMessage = {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
    };
    buf.append(Buffer.from(JSON.stringify(msg) + "\n"));

    const result = buf.readMessage();
    expect(result).toEqual(msg);
  });

  it("should return null when no complete message available", () => {
    const buf = new ReadBuffer();
    buf.append(Buffer.from('{"jsonrpc":"2.0"'));

    const result = buf.readMessage();
    expect(result).toBeNull();
  });

  it("should handle messages split across multiple chunks", () => {
    const buf = new ReadBuffer();
    const msg: JsonRpcMessage = {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "read_file", arguments: { path: "/test" } },
    };
    const full = JSON.stringify(msg) + "\n";
    const mid = Math.floor(full.length / 2);

    buf.append(Buffer.from(full.slice(0, mid)));
    expect(buf.readMessage()).toBeNull();

    buf.append(Buffer.from(full.slice(mid)));
    const result = buf.readMessage();
    expect(result).toEqual(msg);
  });

  it("should parse multiple messages in one chunk", () => {
    const buf = new ReadBuffer();
    const msg1: JsonRpcMessage = { jsonrpc: "2.0", id: 1, method: "a" };
    const msg2: JsonRpcMessage = { jsonrpc: "2.0", id: 2, method: "b" };

    buf.append(
      Buffer.from(JSON.stringify(msg1) + "\n" + JSON.stringify(msg2) + "\n")
    );

    const results = buf.readAllMessages();
    expect(results).toHaveLength(2);
    expect(results[0]).toEqual(msg1);
    expect(results[1]).toEqual(msg2);
  });

  it("should handle \\r\\n line endings (Windows)", () => {
    const buf = new ReadBuffer();
    const msg: JsonRpcMessage = { jsonrpc: "2.0", id: 1, method: "test" };
    buf.append(Buffer.from(JSON.stringify(msg) + "\r\n"));

    const result = buf.readMessage();
    expect(result).toEqual(msg);
  });

  it("should skip empty lines", () => {
    const buf = new ReadBuffer();
    const msg: JsonRpcMessage = { jsonrpc: "2.0", id: 1, method: "test" };
    buf.append(Buffer.from("\n\n" + JSON.stringify(msg) + "\n"));

    const results = buf.readAllMessages();
    expect(results).toHaveLength(1);
    expect(results[0]).toEqual(msg);
  });

  it("should clear the buffer", () => {
    const buf = new ReadBuffer();
    buf.append(Buffer.from("some data"));
    expect(buf.hasPendingData).toBe(true);

    buf.clear();
    expect(buf.hasPendingData).toBe(false);
  });

  it("should throw on invalid JSON", () => {
    const buf = new ReadBuffer();
    buf.append(Buffer.from("not-json\n"));

    expect(() => buf.readMessage()).toThrow();
  });
});

describe("serializeMessage", () => {
  it("should serialize with trailing newline", () => {
    const msg: JsonRpcMessage = { jsonrpc: "2.0", id: 1, method: "test" };
    const result = serializeMessage(msg);
    expect(result).toBe('{"jsonrpc":"2.0","id":1,"method":"test"}\n');
    expect(result.endsWith("\n")).toBe(true);
  });
});

describe("deserializeMessage", () => {
  it("should parse valid JSON-RPC request", () => {
    const line = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}';
    const result = deserializeMessage(line);
    expect(result).toEqual({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "read_file" },
    });
  });

  it("should parse valid JSON-RPC response", () => {
    const line = '{"jsonrpc":"2.0","id":1,"result":{"content":"hello"}}';
    const result = deserializeMessage(line);
    expect(result).toEqual({
      jsonrpc: "2.0",
      id: 1,
      result: { content: "hello" },
    });
  });

  it("should reject non-JSON-RPC messages", () => {
    expect(() => deserializeMessage('{"hello":"world"}')).toThrow();
  });
});
