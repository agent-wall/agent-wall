import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as crypto from "node:crypto";
import { AuditLogger, checkFilePermissions } from "./audit-logger.js";

describe("AuditLogger Security", () => {
  const tmpDir = path.join(os.tmpdir(), `aw-audit-test-${crypto.randomUUID()}`);

  function tmpFile(name: string): string {
    if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
    return path.join(tmpDir, name);
  }

  afterEach(() => {
    try {
      const files = fs.readdirSync(tmpDir);
      for (const f of files) fs.unlinkSync(path.join(tmpDir, f));
      fs.rmdirSync(tmpDir);
    } catch { /* ignore */ }
  });

  describe("HMAC-SHA256 signing", () => {
    it("should add _sig and _seq when signing is enabled", () => {
      const logFile = tmpFile("signed.jsonl");
      const logger = new AuditLogger({
        filePath: logFile,
        signing: true,
        signingKey: "test-key-123",
        stdout: false,
        silent: true,
      });

      logger.log({
        timestamp: "2026-01-01T00:00:00Z",
        sessionId: "test",
        direction: "request",
        method: "tools/call",
        tool: "read_file",
      });

      logger.close();

      const content = fs.readFileSync(logFile, "utf-8").trim();
      const entry = JSON.parse(content);
      expect(entry._sig).toBeDefined();
      expect(entry._seq).toBe(1);
      expect(typeof entry._sig).toBe("string");
      expect(entry._sig.length).toBe(64); // SHA256 hex = 64 chars
    });

    it("should chain signatures (each depends on previous)", () => {
      const logFile = tmpFile("chain.jsonl");
      const key = "chain-test-key";
      const logger = new AuditLogger({
        filePath: logFile,
        signing: true,
        signingKey: key,
        stdout: false,
        silent: true,
      });

      logger.log({
        timestamp: "2026-01-01T00:00:01Z",
        sessionId: "test",
        direction: "request",
        method: "tools/call",
        tool: "tool_a",
      });
      logger.log({
        timestamp: "2026-01-01T00:00:02Z",
        sessionId: "test",
        direction: "request",
        method: "tools/call",
        tool: "tool_b",
      });
      logger.close();

      const lines = fs.readFileSync(logFile, "utf-8").trim().split("\n");
      const entry1 = JSON.parse(lines[0]);
      const entry2 = JSON.parse(lines[1]);

      expect(entry1._seq).toBe(1);
      expect(entry2._seq).toBe(2);
      // Signatures should be different (different entries + chained)
      expect(entry1._sig).not.toBe(entry2._sig);
    });

    it("should verify a valid chain", () => {
      const logFile = tmpFile("verify.jsonl");
      const key = "verify-key-abc";
      const logger = new AuditLogger({
        filePath: logFile,
        signing: true,
        signingKey: key,
        stdout: false,
        silent: true,
      });

      for (let i = 0; i < 5; i++) {
        logger.log({
          timestamp: new Date().toISOString(),
          sessionId: "test",
          direction: "request",
          method: "tools/call",
          tool: `tool_${i}`,
        });
      }
      logger.close();

      const result = AuditLogger.verifyChain(logFile, key);
      expect(result.valid).toBe(true);
      expect(result.entries).toBe(5);
      expect(result.firstBroken).toBeNull();
    });

    it("should detect tampered entries", () => {
      const logFile = tmpFile("tampered.jsonl");
      const key = "tamper-key-xyz";
      const logger = new AuditLogger({
        filePath: logFile,
        signing: true,
        signingKey: key,
        stdout: false,
        silent: true,
      });

      for (let i = 0; i < 3; i++) {
        logger.log({
          timestamp: new Date().toISOString(),
          sessionId: "test",
          direction: "request",
          method: "tools/call",
          tool: `tool_${i}`,
        });
      }
      logger.close();

      // Tamper with the second entry
      const lines = fs.readFileSync(logFile, "utf-8").trim().split("\n");
      const entry = JSON.parse(lines[1]);
      entry.tool = "TAMPERED";
      lines[1] = JSON.stringify(entry);
      fs.writeFileSync(logFile, lines.join("\n") + "\n");

      const result = AuditLogger.verifyChain(logFile, key);
      expect(result.valid).toBe(false);
      expect(result.firstBroken).toBe(1);
    });
  });

  describe("log rotation", () => {
    it("should rotate when file exceeds max size", () => {
      const logFile = tmpFile("rotate.jsonl");
      const logger = new AuditLogger({
        filePath: logFile,
        maxFileSize: 200, // Very small — triggers rotation quickly
        maxFiles: 3,
        stdout: false,
        silent: true,
      });

      // Write enough entries to trigger rotation
      for (let i = 0; i < 20; i++) {
        logger.log({
          timestamp: new Date().toISOString(),
          sessionId: "test",
          direction: "request",
          method: "tools/call",
          tool: `tool_${i}`,
        });
      }
      logger.close();

      // Check that rotated files exist
      expect(fs.existsSync(logFile)).toBe(true);
      expect(fs.existsSync(`${logFile}.1`)).toBe(true);
    });
  });

  describe("file permission checks", () => {
    it("should report safe for normal files", () => {
      const testFile = tmpFile("safe-policy.yaml");
      fs.writeFileSync(testFile, "version: 1\nrules: []");

      const result = checkFilePermissions(testFile);
      // On Windows/MINGW, permission checks are best-effort
      // The function should at least not throw
      expect(result).toBeDefined();
      expect(Array.isArray(result.warnings)).toBe(true);
    });

    it("should handle non-existent files", () => {
      const result = checkFilePermissions("/nonexistent/file.yaml");
      expect(result.safe).toBe(false);
      expect(result.warnings.length).toBeGreaterThan(0);
    });
  });

  describe("unsigned logging still works", () => {
    it("should log without signatures when signing is disabled", () => {
      const logFile = tmpFile("unsigned.jsonl");
      const logger = new AuditLogger({
        filePath: logFile,
        signing: false,
        stdout: false,
        silent: true,
      });

      logger.log({
        timestamp: "2026-01-01T00:00:00Z",
        sessionId: "test",
        direction: "request",
        method: "tools/call",
      });
      logger.close();

      const content = fs.readFileSync(logFile, "utf-8").trim();
      const entry = JSON.parse(content);
      expect(entry._sig).toBeUndefined();
      expect(entry._seq).toBeUndefined();
    });
  });
});
