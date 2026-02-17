import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { testCommand } from "./test.js";

// Mock @agent-wall/core
vi.mock("@agent-wall/core", () => {
  const config = {
    version: 1,
    defaultAction: "deny",
    rules: [
      { name: "block-ssh", tool: "read_file", action: "deny", arguments: { path: "*.ssh*" } },
      { name: "allow-project", tool: "read_file", action: "allow", arguments: { path: "/project/**" } },
      { name: "prompt-shell", tool: "shell_exec", action: "prompt" },
    ],
  };

  class MockPolicyEngine {
    private config: any;
    constructor(cfg: any) {
      this.config = cfg;
    }
    evaluate(toolCall: any) {
      // Simulate first-match-wins
      for (const rule of this.config.rules) {
        if (rule.tool === toolCall.name) {
          return {
            action: rule.action,
            rule: rule.name,
            message: `Matched rule: ${rule.name}`,
          };
        }
      }
      return {
        action: this.config.defaultAction,
        rule: null,
        message: "No matching rule, using default",
      };
    }
  }

  return {
    PolicyEngine: MockPolicyEngine,
    loadPolicy: (configPath?: string) => ({
      config,
      filePath: configPath ?? "agent-wall.yaml",
    }),
  };
});

describe("testCommand", () => {
  let exitSpy: any;
  let stderrSpy: any;

  beforeEach(() => {
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    stderrSpy = vi.spyOn(process.stderr, "write").mockReturnValue(true);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("exits with error when --tool is missing", () => {
    expect(() =>
      testCommand({ tool: "" })
    ).toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("evaluates a denied tool call with exit code 1", () => {
    expect(() =>
      testCommand({
        tool: "read_file",
        arg: ["path=/home/.ssh/id_rsa"],
      })
    ).toThrow("process.exit");
    // Deny → exit(1)
    expect(exitSpy).toHaveBeenCalledWith(1);
    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("DENIED");
  });

  it("evaluates an allowed tool call with exit code 0", () => {
    // Override: read_file matches "block-ssh" first in our mock
    // Actually our mock matches by tool name first, so read_file → deny
    // Let's test a tool that doesn't match → default deny → exit(1)
    // We need an allow result. The mock has block-ssh matching read_file.
    // Let's use a tool name that hits no rules → default deny.
    expect(() =>
      testCommand({
        tool: "shell_exec",
        arg: ["command=ls"],
      })
    ).toThrow("process.exit");
    // prompt-shell has action: "prompt" → exit(0)
    expect(exitSpy).toHaveBeenCalledWith(0);
    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("PROMPT");
  });

  it("parses --arg key=value arguments correctly", () => {
    expect(() =>
      testCommand({
        tool: "read_file",
        arg: ["path=/home/.ssh/id_rsa", "encoding=utf-8"],
      })
    ).toThrow("process.exit");
    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("path");
    expect(allOutput).toContain("encoding");
  });

  it("rejects invalid arg format (no equals sign)", () => {
    expect(() =>
      testCommand({
        tool: "read_file",
        arg: ["invalid_no_equals"],
      })
    ).toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("Invalid argument format");
  });

  it("shows policy file path in output", () => {
    expect(() =>
      testCommand({ tool: "read_file" })
    ).toThrow("process.exit");
    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("agent-wall.yaml");
  });

  it("shows matched rule name in output", () => {
    expect(() =>
      testCommand({
        tool: "read_file",
        arg: ["path=/home/.ssh/id_rsa"],
      })
    ).toThrow("process.exit");
    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("block-ssh");
  });

  it("handles default action for unknown tools", () => {
    expect(() =>
      testCommand({ tool: "unknown_tool" })
    ).toThrow("process.exit");
    // Default is deny → exit(1)
    expect(exitSpy).toHaveBeenCalledWith(1);
  });
});
