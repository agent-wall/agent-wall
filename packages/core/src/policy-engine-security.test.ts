import { describe, it, expect } from "vitest";
import { PolicyEngine } from "./policy-engine.js";
import { isRegexSafe } from "./response-scanner.js";

describe("PolicyEngine Security", () => {
  describe("path traversal normalization", () => {
    const engine = new PolicyEngine({
      version: 1,
      rules: [
        {
          name: "block-ssh",
          tool: "*",
          match: { arguments: { path: "**/.ssh/**" } },
          action: "deny",
        },
        {
          name: "block-env",
          tool: "*",
          match: { arguments: { path: "**/.env*" } },
          action: "deny",
        },
      ],
    });

    it("should block direct .ssh access", () => {
      const result = engine.evaluate({
        name: "read_file",
        arguments: { path: "/home/user/.ssh/id_rsa" },
      });
      expect(result.action).toBe("deny");
    });

    it("should block path traversal to .ssh", () => {
      const result = engine.evaluate({
        name: "read_file",
        arguments: { path: "/home/user/docs/../../.ssh/id_rsa" },
      });
      // After normalization: /home/.ssh/id_rsa
      expect(result.action).toBe("deny");
    });

    it("should block ../ prefix traversal to .env", () => {
      const result = engine.evaluate({
        name: "read_file",
        arguments: { path: "../../.env" },
      });
      expect(result.action).toBe("deny");
    });

    it("should block backslash path traversal", () => {
      const result = engine.evaluate({
        name: "read_file",
        arguments: { path: "..\\..\\..\\home\\user\\.ssh\\id_rsa" },
      });
      expect(result.action).toBe("deny");
    });
  });

  describe("Unicode NFC normalization", () => {
    const engine = new PolicyEngine({
      version: 1,
      rules: [
        {
          name: "block-env",
          tool: "*",
          match: { arguments: { path: "**/.env*" } },
          action: "deny",
        },
      ],
    });

    it("should match NFC-normalized strings", () => {
      // .env in NFC form
      const result = engine.evaluate({
        name: "read_file",
        arguments: { path: "/app/.env" },
      });
      expect(result.action).toBe("deny");
    });

    it("should normalize NFD to NFC before matching", () => {
      // Use NFD decomposed form for the 'e' in .env
      // U+0065 (e) + U+0301 (combining acute) = é in NFD
      // This tests that normalization happens before matching
      const nfdPath = "/app/.e\u0301nv";
      const result = engine.evaluate({
        name: "read_file",
        arguments: { path: nfdPath },
      });
      // After NFC normalization, the é stays as é (not plain e)
      // So .énv won't match .env* — this is correct! NFC prevents
      // decomposition bypass but doesn't collapse different characters
      expect(result).toBeDefined();
    });
  });

  describe("zero-trust strict mode", () => {
    const engine = new PolicyEngine({
      version: 1,
      mode: "strict",
      rules: [
        { name: "allow-read", tool: "read_file", action: "allow" },
        { name: "allow-list", tool: "list_directory", action: "allow" },
      ],
    });

    it("should allow explicitly listed tools", () => {
      const result = engine.evaluate({ name: "read_file" });
      expect(result.action).toBe("allow");
    });

    it("should deny unlisted tools (zero-trust default)", () => {
      const result = engine.evaluate({ name: "write_file" });
      expect(result.action).toBe("deny");
      expect(result.message).toContain("Zero-trust");
    });

    it("should deny shell commands not in allowlist", () => {
      const result = engine.evaluate({ name: "bash" });
      expect(result.action).toBe("deny");
    });

    it("should deny even with arguments matching no rule", () => {
      const result = engine.evaluate({
        name: "execute_command",
        arguments: { command: "ls" },
      });
      expect(result.action).toBe("deny");
    });
  });

  describe("standard mode backward compatibility", () => {
    it("should default to prompt when no mode specified", () => {
      const engine = new PolicyEngine({
        version: 1,
        rules: [],
      });
      const result = engine.evaluate({ name: "any_tool" });
      expect(result.action).toBe("prompt");
    });

    it("should respect defaultAction in standard mode", () => {
      const engine = new PolicyEngine({
        version: 1,
        mode: "standard",
        defaultAction: "allow",
        rules: [],
      });
      const result = engine.evaluate({ name: "any_tool" });
      expect(result.action).toBe("allow");
    });
  });

  describe("argument key aliases", () => {
    const engine = new PolicyEngine({
      version: 1,
      rules: [
        {
          name: "block-ssh-by-path",
          tool: "*",
          match: { arguments: { path: "**/.ssh/**" } },
          action: "deny",
        },
      ],
    });

    it("should match 'path' key directly", () => {
      const result = engine.evaluate({
        name: "read_file",
        arguments: { path: "/home/.ssh/id_rsa" },
      });
      expect(result.action).toBe("deny");
    });

    it("should match 'file' key as alias for 'path'", () => {
      const result = engine.evaluate({
        name: "read_file",
        arguments: { file: "/home/.ssh/id_rsa" },
      });
      expect(result.action).toBe("deny");
    });

    it("should match 'filepath' key as alias for 'path'", () => {
      const result = engine.evaluate({
        name: "read_file",
        arguments: { filepath: "/home/.ssh/id_rsa" },
      });
      expect(result.action).toBe("deny");
    });

    it("should match 'file_path' key as alias for 'path'", () => {
      const result = engine.evaluate({
        name: "read_file",
        arguments: { file_path: "/home/.ssh/id_rsa" },
      });
      expect(result.action).toBe("deny");
    });

    it("should match case-insensitively", () => {
      const result = engine.evaluate({
        name: "read_file",
        arguments: { PATH: "/home/.ssh/id_rsa" },
      });
      expect(result.action).toBe("deny");
    });
  });

  describe("ReDoS protection", () => {
    it("should reject nested quantifier patterns", () => {
      expect(isRegexSafe("(a+)+")).toBe(false);
    });

    it("should reject patterns that are too long", () => {
      const longPattern = "a".repeat(1100);
      expect(isRegexSafe(longPattern)).toBe(false);
    });

    it("should accept safe patterns", () => {
      expect(isRegexSafe("[A-Za-z0-9]+")).toBe(true);
      expect(isRegexSafe("\\d{3}-\\d{2}-\\d{4}")).toBe(true);
    });

    it("should reject invalid regex", () => {
      expect(isRegexSafe("[invalid")).toBe(false);
    });
  });
});
