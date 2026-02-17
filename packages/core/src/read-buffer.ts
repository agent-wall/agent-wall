/**
 * Agent Wall Read Buffer
 *
 * Accumulates raw bytes from a stream and extracts
 * newline-delimited JSON-RPC messages one at a time.
 *
 * Directly mirrors the MCP SDK's ReadBuffer pattern:
 *   - Append raw chunks
 *   - Scan for '\n' delimiter
 *   - Extract line, strip '\r', JSON.parse, validate
 *
 * Security: Enforces maximum buffer size to prevent DOS
 * via unbounded memory growth from a single large message.
 */

import { JsonRpcMessage, JsonRpcMessageSchema } from "./types.js";

/** Default max buffer size: 10MB */
const DEFAULT_MAX_BUFFER_SIZE = 10 * 1024 * 1024;

export class ReadBuffer {
  private buffer: Buffer | null = null;
  private maxBufferSize: number;

  constructor(maxBufferSize: number = DEFAULT_MAX_BUFFER_SIZE) {
    this.maxBufferSize = maxBufferSize;
  }

  /**
   * Append raw bytes from a stream chunk.
   * Throws if the buffer exceeds the configured maximum size.
   */
  append(chunk: Buffer): void {
    this.buffer = this.buffer ? Buffer.concat([this.buffer, chunk]) : chunk;
    if (this.buffer.length > this.maxBufferSize) {
      const size = this.buffer.length;
      this.buffer = null;
      throw new BufferOverflowError(
        `Buffer size ${size} exceeds maximum ${this.maxBufferSize} bytes — possible DOS attack`
      );
    }
  }

  /**
   * Try to extract the next complete JSON-RPC message.
   * Returns null if no complete message is available yet.
   * Automatically skips empty lines.
   */
  readMessage(): JsonRpcMessage | null {
    while (this.buffer) {
      const index = this.buffer.indexOf("\n");
      if (index === -1) return null;

      // Extract the line (strip trailing \r for Windows compatibility)
      const line = this.buffer.toString("utf8", 0, index).replace(/\r$/, "");
      this.buffer = this.buffer.subarray(index + 1);

      // Normalize: discard buffer reference if empty
      if (this.buffer.length === 0) this.buffer = null;

      // Skip empty lines
      if (line.length === 0) continue;

      return deserializeMessage(line);
    }
    return null;
  }

  /**
   * Extract ALL available messages from the buffer.
   */
  readAllMessages(): JsonRpcMessage[] {
    const messages: JsonRpcMessage[] = [];
    let msg: JsonRpcMessage | null;
    while ((msg = this.readMessage()) !== null) {
      messages.push(msg);
    }
    return messages;
  }

  /**
   * Clear the buffer.
   */
  clear(): void {
    this.buffer = null;
  }

  /**
   * Check if there's any pending data in the buffer.
   */
  get hasPendingData(): boolean {
    return this.buffer !== null && this.buffer.length > 0;
  }

  /**
   * Get current buffer size in bytes.
   */
  get currentSize(): number {
    return this.buffer?.length ?? 0;
  }
}

/**
 * Error thrown when buffer exceeds maximum size.
 */
export class BufferOverflowError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BufferOverflowError";
  }
}

/**
 * Parse a single line of text into a validated JSON-RPC message.
 */
export function deserializeMessage(line: string): JsonRpcMessage {
  const parsed = JSON.parse(line);
  return JsonRpcMessageSchema.parse(parsed);
}

/**
 * Serialize a JSON-RPC message to a newline-delimited string.
 */
export function serializeMessage(message: JsonRpcMessage): string {
  return JSON.stringify(message) + "\n";
}
