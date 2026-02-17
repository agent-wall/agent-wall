/**
 * Tests for ResponseScanner — response content scanning and redaction.
 */

import { describe, it, expect } from "vitest";
import {
  ResponseScanner,
  createDefaultScanner,
  type ResponseScannerConfig,
} from "./response-scanner.js";

describe("ResponseScanner", () => {
  describe("basic functionality", () => {
    it("should pass clean text through", () => {
      const scanner = new ResponseScanner({ detectSecrets: true });
      const result = scanner.scan("Hello world, this is a normal response.");
      expect(result.clean).toBe(true);
      expect(result.action).toBe("pass");
      expect(result.findings).toHaveLength(0);
    });

    it("should be disabled when enabled=false", () => {
      const scanner = new ResponseScanner({
        enabled: false,
        detectSecrets: true,
      });
      // Even with secrets present, a disabled scanner passes everything
      const result = scanner.scan("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
      expect(result.clean).toBe(true);
      expect(result.action).toBe("pass");
    });

    it("should return original size in bytes", () => {
      const scanner = new ResponseScanner();
      const text = "hello world";
      const result = scanner.scan(text);
      expect(result.originalSize).toBe(Buffer.byteLength(text, "utf-8"));
    });
  });

  describe("secret detection", () => {
    it("should detect AWS access key IDs", () => {
      const scanner = new ResponseScanner({ detectSecrets: true });
      const result = scanner.scan("Found key: AKIAIOSFODNN7EXAMPLE in config");
      expect(result.clean).toBe(false);
      expect(result.findings.some((f) => f.pattern === "aws-access-key")).toBe(true);
    });

    it("should detect AWS secret access keys", () => {
      const scanner = new ResponseScanner({ detectSecrets: true });
      const result = scanner.scan(
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      );
      expect(result.clean).toBe(false);
      expect(result.action).toBe("redact");
      expect(result.findings.some((f) => f.pattern === "aws-secret-key")).toBe(true);
    });

    it("should detect GitHub tokens", () => {
      const scanner = new ResponseScanner({ detectSecrets: true });
      const result = scanner.scan(
        "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"
      );
      expect(result.clean).toBe(false);
      expect(result.findings.some((f) => f.pattern === "github-token")).toBe(true);
    });

    it("should detect generic API keys", () => {
      const scanner = new ResponseScanner({ detectSecrets: true });
      const result = scanner.scan(
        'config = { api_key: "sk_live_1234567890abcdefghij" }'
      );
      expect(result.clean).toBe(false);
      expect(result.findings.some((f) => f.pattern === "generic-api-key")).toBe(true);
    });

    it("should detect Bearer tokens", () => {
      const scanner = new ResponseScanner({ detectSecrets: true });
      const result = scanner.scan(
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test.signature"
      );
      expect(result.clean).toBe(false);
      // Could match bearer-token and/or jwt-token
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it("should detect JWT tokens", () => {
      const scanner = new ResponseScanner({ detectSecrets: true });
      const result = scanner.scan(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
      );
      expect(result.clean).toBe(false);
      expect(result.findings.some((f) => f.pattern === "jwt-token")).toBe(true);
    });

    it("should BLOCK when a private key is detected", () => {
      const scanner = new ResponseScanner({ detectSecrets: true });
      const result = scanner.scan(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
      );
      expect(result.clean).toBe(false);
      expect(result.action).toBe("block");
      expect(result.findings.some((f) => f.pattern === "private-key")).toBe(true);
    });

    it("should detect database connection strings", () => {
      const scanner = new ResponseScanner({ detectSecrets: true });
      const result = scanner.scan(
        "DATABASE_URL=postgres://admin:s3cret@db.example.com:5432/mydb"
      );
      expect(result.clean).toBe(false);
      expect(result.findings.some((f) => f.pattern === "database-url")).toBe(true);
    });

    it("should detect password assignments", () => {
      const scanner = new ResponseScanner({ detectSecrets: true });
      const result = scanner.scan('password = "SuperSecret123!"');
      expect(result.clean).toBe(false);
      expect(result.findings.some((f) => f.pattern === "password-assignment")).toBe(true);
    });

    it("should not detect secrets when detectSecrets=false", () => {
      const scanner = new ResponseScanner({ detectSecrets: false });
      const result = scanner.scan("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
      expect(result.clean).toBe(true);
    });
  });

  describe("PII detection", () => {
    it("should not detect PII by default", () => {
      const scanner = new ResponseScanner({ detectSecrets: false, detectPII: false });
      const result = scanner.scan("Email: john@example.com Phone: 555-123-4567");
      expect(result.clean).toBe(true);
    });

    it("should detect email addresses when PII detection enabled", () => {
      const scanner = new ResponseScanner({ detectPII: true, detectSecrets: false });
      const result = scanner.scan("Contact: user@example.com for details");
      expect(result.clean).toBe(false);
      expect(result.findings.some((f) => f.pattern === "email-address")).toBe(true);
    });

    it("should detect phone numbers when PII detection enabled", () => {
      const scanner = new ResponseScanner({ detectPII: true, detectSecrets: false });
      const result = scanner.scan("Call us at (555) 123-4567");
      expect(result.clean).toBe(false);
      expect(result.findings.some((f) => f.pattern === "phone-number")).toBe(true);
    });

    it("should BLOCK SSN patterns", () => {
      const scanner = new ResponseScanner({ detectPII: true, detectSecrets: false });
      const result = scanner.scan("SSN: 123-45-6789");
      expect(result.clean).toBe(false);
      expect(result.action).toBe("block");
      expect(result.findings.some((f) => f.pattern === "ssn")).toBe(true);
    });

    it("should BLOCK credit card numbers", () => {
      const scanner = new ResponseScanner({ detectPII: true, detectSecrets: false });
      const result = scanner.scan("Card: 4111111111111111");
      expect(result.clean).toBe(false);
      expect(result.action).toBe("block");
      expect(result.findings.some((f) => f.pattern === "credit-card")).toBe(true);
    });
  });

  describe("response size limits", () => {
    it("should flag oversized responses", () => {
      const scanner = new ResponseScanner({
        maxResponseSize: 100,
        oversizeAction: "redact",
        detectSecrets: false,
      });
      const bigText = "A".repeat(200);
      const result = scanner.scan(bigText);
      expect(result.clean).toBe(false);
      expect(result.findings.some((f) => f.pattern === "__oversize__")).toBe(true);
    });

    it("should block oversized when oversizeAction=block", () => {
      const scanner = new ResponseScanner({
        maxResponseSize: 50,
        oversizeAction: "block",
        detectSecrets: false,
      });
      const result = scanner.scan("A".repeat(100));
      expect(result.action).toBe("block");
    });

    it("should redact (truncate) when oversizeAction=redact", () => {
      const scanner = new ResponseScanner({
        maxResponseSize: 50,
        oversizeAction: "redact",
        detectSecrets: false,
      });
      const result = scanner.scan("A".repeat(100));
      expect(result.action).toBe("redact");
      expect(result.redactedText).toBeDefined();
      expect(result.redactedText!.length).toBeLessThan(200);
    });

    it("should not flag responses under the size limit", () => {
      const scanner = new ResponseScanner({
        maxResponseSize: 1000,
        detectSecrets: false,
      });
      const result = scanner.scan("short text");
      expect(result.clean).toBe(true);
    });

    it("should not check size when maxResponseSize=0", () => {
      const scanner = new ResponseScanner({
        maxResponseSize: 0,
        detectSecrets: false,
      });
      const result = scanner.scan("A".repeat(10000));
      expect(result.clean).toBe(true);
    });
  });

  describe("custom patterns", () => {
    it("should match user-defined patterns", () => {
      const scanner = new ResponseScanner({
        detectSecrets: false,
        patterns: [
          {
            name: "internal-url",
            pattern: "https?://internal\\.[a-z]+\\.corp",
            action: "redact",
            message: "Internal URL detected",
            category: "custom",
          },
        ],
      });
      const result = scanner.scan("API endpoint: https://internal.api.corp/v1/users");
      expect(result.clean).toBe(false);
      expect(result.findings.some((f) => f.pattern === "internal-url")).toBe(true);
    });

    it("should block on custom block patterns", () => {
      const scanner = new ResponseScanner({
        detectSecrets: false,
        patterns: [
          {
            name: "confidential-marker",
            pattern: "\\[CONFIDENTIAL\\]",
            action: "block",
            message: "Confidential content detected",
          },
        ],
      });
      const result = scanner.scan("This document is [CONFIDENTIAL] and should not be shared.");
      expect(result.action).toBe("block");
    });

    it("should skip invalid regex patterns without crashing", () => {
      const scanner = new ResponseScanner({
        detectSecrets: false,
        patterns: [
          {
            name: "bad-pattern",
            pattern: "[invalid(regex",
            action: "block",
          },
          {
            name: "good-pattern",
            pattern: "findme",
            action: "redact",
          },
        ],
      });
      // Should not throw, and should still find the good pattern
      const result = scanner.scan("please findme in this text");
      expect(result.clean).toBe(false);
      expect(result.findings.some((f) => f.pattern === "good-pattern")).toBe(true);
    });

    it("should report match counts", () => {
      const scanner = new ResponseScanner({
        detectSecrets: false,
        patterns: [
          {
            name: "word-secret",
            pattern: "secret",
            flags: "gi",
            action: "redact",
          },
        ],
      });
      const result = scanner.scan("secret one, SECRET two, Secret three");
      expect(result.findings[0].matchCount).toBe(3);
    });
  });

  describe("action priority", () => {
    it("block beats redact", () => {
      const scanner = new ResponseScanner({
        detectSecrets: false,
        patterns: [
          { name: "p1", pattern: "aaa", action: "redact" },
          { name: "p2", pattern: "bbb", action: "block" },
        ],
      });
      const result = scanner.scan("aaa and bbb");
      expect(result.action).toBe("block");
    });

    it("redact beats pass", () => {
      const scanner = new ResponseScanner({
        detectSecrets: false,
        patterns: [
          { name: "p1", pattern: "aaa", action: "pass" },
          { name: "p2", pattern: "bbb", action: "redact" },
        ],
      });
      const result = scanner.scan("aaa and bbb");
      expect(result.action).toBe("redact");
    });
  });

  describe("redaction", () => {
    it("should replace matched patterns with generic [REDACTED] marker", () => {
      const scanner = new ResponseScanner({
        detectSecrets: false,
        patterns: [
          {
            name: "secret-word",
            pattern: "s3cr3t",
            flags: "gi",
            action: "redact",
          },
        ],
      });
      const result = scanner.scan("The password is s3cr3t okay?");
      expect(result.redactedText).toContain("[REDACTED]");
      // Security: redaction marker must NOT leak the pattern name
      expect(result.redactedText).not.toContain("secret-word");
      expect(result.redactedText).not.toContain("s3cr3t");
    });
  });

  describe("MCP response scanning", () => {
    it("should extract text from MCP content array", () => {
      const scanner = new ResponseScanner({
        detectSecrets: false,
        patterns: [{ name: "test", pattern: "DANGER", action: "block" }],
      });
      const mcpResult = {
        content: [
          { type: "text", text: "This is DANGER zone" },
        ],
      };
      const result = scanner.scanMcpResponse(mcpResult);
      expect(result.clean).toBe(false);
      expect(result.action).toBe("block");
    });

    it("should handle string results", () => {
      const scanner = new ResponseScanner({
        detectSecrets: false,
        patterns: [{ name: "test", pattern: "DANGER", action: "redact" }],
      });
      const result = scanner.scanMcpResponse("Contains DANGER data");
      expect(result.clean).toBe(false);
    });

    it("should handle null/undefined results", () => {
      const scanner = new ResponseScanner({ detectSecrets: true });
      const result = scanner.scanMcpResponse(null);
      expect(result.clean).toBe(true);
    });

    it("should join multiple text content blocks", () => {
      const scanner = new ResponseScanner({
        detectSecrets: false,
        patterns: [{ name: "multi", pattern: "part1.*part2", flags: "gs", action: "redact" }],
      });
      const mcpResult = {
        content: [
          { type: "text", text: "part1" },
          { type: "text", text: "part2" },
        ],
      };
      const result = scanner.scanMcpResponse(mcpResult);
      expect(result.clean).toBe(false);
    });

    it("should skip non-text content blocks", () => {
      const scanner = new ResponseScanner({
        detectSecrets: false,
        patterns: [{ name: "test", pattern: "image-data", action: "block" }],
      });
      const mcpResult = {
        content: [
          { type: "image", data: "image-data" },
          { type: "text", text: "safe text" },
        ],
      };
      const result = scanner.scanMcpResponse(mcpResult);
      expect(result.clean).toBe(true);
    });
  });

  describe("configuration", () => {
    it("should report pattern count", () => {
      const scanner = new ResponseScanner({
        detectSecrets: true,
        detectPII: true,
        patterns: [
          { name: "custom1", pattern: "test1", action: "pass" },
          { name: "custom2", pattern: "test2", action: "pass" },
        ],
      });
      // Built-in secrets + PII + 2 custom
      expect(scanner.getPatternCount()).toBeGreaterThan(10);
    });

    it("should update config dynamically", () => {
      const scanner = new ResponseScanner({ detectSecrets: true });
      expect(scanner.getConfig().detectSecrets).toBe(true);

      scanner.updateConfig({ detectSecrets: false });
      expect(scanner.getConfig().detectSecrets).toBe(false);

      // After update, secrets should not be detected
      const result = scanner.scan("AKIAIOSFODNN7EXAMPLE");
      expect(result.clean).toBe(true);
    });
  });

  describe("createDefaultScanner", () => {
    it("should create a scanner with sensible defaults", () => {
      const scanner = createDefaultScanner();
      expect(scanner.getConfig().enabled).toBe(true);
      expect(scanner.getConfig().detectSecrets).toBe(true);
      expect(scanner.getConfig().detectPII).toBe(false);
      expect(scanner.getConfig().maxResponseSize).toBe(5 * 1024 * 1024);
      expect(scanner.getPatternCount()).toBeGreaterThan(0);
    });

    it("should detect a private key with the default scanner", () => {
      const scanner = createDefaultScanner();
      const result = scanner.scan("-----BEGIN PRIVATE KEY-----\nblahblah\n-----END PRIVATE KEY-----");
      expect(result.action).toBe("block");
    });
  });

  describe("preview generation", () => {
    it("should create masked previews of matched content", () => {
      const scanner = new ResponseScanner({
        detectSecrets: false,
        patterns: [
          { name: "long-match", pattern: "supersecretlongvalue", action: "redact" },
        ],
      });
      const result = scanner.scan("value is supersecretlongvalue here");
      expect(result.findings[0].preview).toBeDefined();
      const preview = result.findings[0].preview!;
      // Should mask the middle
      expect(preview).toContain("...");
      expect(preview.length).toBeLessThan("supersecretlongvalue".length);
    });
  });
});
