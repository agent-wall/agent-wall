import { describe, it, expect } from "vitest";
import { ReadBuffer, BufferOverflowError } from "./read-buffer.js";

describe("ReadBuffer Security", () => {
  describe("overflow protection", () => {
    it("should accept data within the default limit", () => {
      const buf = new ReadBuffer();
      const chunk = Buffer.alloc(1000, "a");
      expect(() => buf.append(chunk)).not.toThrow();
    });

    it("should throw BufferOverflowError when exceeding limit", () => {
      const buf = new ReadBuffer(100); // 100 byte limit
      const chunk = Buffer.alloc(200, "a");
      expect(() => buf.append(chunk)).toThrow(BufferOverflowError);
    });

    it("should clear buffer after overflow", () => {
      const buf = new ReadBuffer(100);
      try {
        buf.append(Buffer.alloc(200, "a"));
      } catch {
        // expected
      }
      expect(buf.hasPendingData).toBe(false);
      expect(buf.currentSize).toBe(0);
    });

    it("should throw when accumulated chunks exceed limit", () => {
      const buf = new ReadBuffer(100);
      buf.append(Buffer.alloc(60, "a"));
      expect(() => buf.append(Buffer.alloc(60, "b"))).toThrow(BufferOverflowError);
    });

    it("should work normally after extracting messages frees space", () => {
      const buf = new ReadBuffer(200);
      const msg = JSON.stringify({ jsonrpc: "2.0", method: "test" }) + "\n";
      buf.append(Buffer.from(msg));
      const result = buf.readMessage();
      expect(result).not.toBeNull();
      expect(buf.currentSize).toBe(0);
    });

    it("should respect custom buffer size", () => {
      const buf = new ReadBuffer(50);
      expect(() => buf.append(Buffer.alloc(51, "x"))).toThrow(BufferOverflowError);
    });

    it("should include size info in error message", () => {
      const buf = new ReadBuffer(100);
      try {
        buf.append(Buffer.alloc(200, "a"));
      } catch (err) {
        expect((err as Error).message).toContain("200");
        expect((err as Error).message).toContain("100");
      }
    });
  });
});
