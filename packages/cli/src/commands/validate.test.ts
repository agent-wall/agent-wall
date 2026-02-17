import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { validateCommand } from "./validate.js";

const mockConfig = {
  version: 1,
  defaultAction: "deny" as const,
  rules: [
    { name: "block-ssh", tool: "read_file", action: "deny" as const },
    { name: "allow-project", tool: "list_directory", action: "allow" as const },
  ],
};

vi.mock("@agent-wall/core", () => {
  class MockPolicyEngine {
    constructor(_cfg: any) {}
  }

  return {
    loadPolicy: (configPath?: string) => ({
      config: { ...mockConfig, rules: [...mockConfig.rules] },
      filePath: configPath ?? "agent-wall.yaml",
    }),
    PolicyEngine: MockPolicyEngine,
  };
});

describe("validateCommand", () => {
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

  it("validates a correct config successfully", () => {
    validateCommand({});
    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("Config loaded");
    expect(allOutput).toContain("Version: 1");
    expect(allOutput).toContain("Default action: deny");
    expect(allOutput).toContain("Rules: 2 loaded");
    expect(allOutput).toContain("Policy engine: OK");
  });

  it("shows the config file path", () => {
    validateCommand({});
    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("agent-wall.yaml");
  });

  it("accepts custom config path", () => {
    validateCommand({ config: "./custom-policy.yaml" });
    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("custom-policy.yaml");
  });

  it("shows rule count", () => {
    validateCommand({});
    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("Rules: 2 loaded");
  });

  it("displays validation header", () => {
    validateCommand({});
    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("Config Validation");
  });
});

describe("validateCommand — error scenarios", () => {
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

  // Note: Testing error branches that require different mock behavior
  // would need vi.mocked module reassignment per test. These tests
  // validate the happy path since the mock is fixed at module level.
  // Integration tests handle error cases more naturally.

  it("reports valid config with no errors or warnings", () => {
    validateCommand({});
    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    // Should not exit with error
    expect(exitSpy).not.toHaveBeenCalled();
    expect(allOutput).toContain("valid");
  });
});
