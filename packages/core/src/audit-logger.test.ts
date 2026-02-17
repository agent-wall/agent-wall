/**
 * Tests for AuditLogger — structured logging.
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { AuditLogger } from "./audit-logger.js";

describe("AuditLogger", () => {
  it("should store logged entries", () => {
    const logger = new AuditLogger({ stdout: false, silent: true });

    logger.logAllow("sess-1", "read_file", { path: "/test" }, "allow-read", "Allowed");
    logger.logDeny("sess-1", "shell_exec", { command: "rm -rf /" }, "block-shell", "Blocked");

    const entries = logger.getEntries();
    expect(entries).toHaveLength(2);
    expect(entries[0].verdict?.action).toBe("allow");
    expect(entries[1].verdict?.action).toBe("deny");
  });

  it("should compute stats correctly", () => {
    const logger = new AuditLogger({ stdout: false, silent: true });

    logger.logAllow("s", "a", {}, null, "");
    logger.logAllow("s", "b", {}, null, "");
    logger.logDeny("s", "c", {}, null, "");

    const stats = logger.getStats();
    expect(stats.total).toBe(3);
    expect(stats.allowed).toBe(2);
    expect(stats.denied).toBe(1);
    expect(stats.prompted).toBe(0);
  });

  it("should redact sensitive argument keys", () => {
    const logger = new AuditLogger({ stdout: false, silent: true, redact: true });

    logger.log({
      timestamp: new Date().toISOString(),
      sessionId: "s",
      direction: "request",
      method: "tools/call",
      tool: "api_call",
      arguments: {
        api_key: "sk-12345secret",
        url: "https://example.com",
        password: "hunter2",
      },
    });

    const entries = logger.getEntries();
    expect(entries[0].arguments?.api_key).toBe("[REDACTED]");
    expect(entries[0].arguments?.password).toBe("[REDACTED]");
    expect(entries[0].arguments?.url).toBe("https://example.com");
  });

  it("should truncate long argument values", () => {
    const logger = new AuditLogger({
      stdout: false,
      silent: true,
      redact: true,
      maxArgLength: 50,
    });

    const longValue = "a".repeat(200);
    logger.log({
      timestamp: new Date().toISOString(),
      sessionId: "s",
      direction: "request",
      method: "tools/call",
      arguments: { content: longValue },
    });

    const entries = logger.getEntries();
    const content = entries[0].arguments?.content as string;
    expect(content.length).toBeLessThan(200);
    expect(content).toContain("[truncated]");
  });

  it("should not redact when disabled", () => {
    const logger = new AuditLogger({ stdout: false, silent: true, redact: false });

    logger.log({
      timestamp: new Date().toISOString(),
      sessionId: "s",
      direction: "request",
      method: "tools/call",
      arguments: { api_key: "visible" },
    });

    expect(logger.getEntries()[0].arguments?.api_key).toBe("visible");
  });
});
