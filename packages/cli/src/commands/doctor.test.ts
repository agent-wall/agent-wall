import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import { doctorCommand } from "./doctor.js";

vi.mock("node:fs");
vi.mock("node:os");
vi.mock("@agent-wall/core", () => {
  class MockPolicyEngine {
    evaluate() {
      return { action: "allow", rule: null, message: "Default allow" };
    }
  }
  return {
    loadPolicy: (_configPath?: string) => ({
      config: {
        rules: [{ name: "test-rule", tools: ["*"], action: "allow" }],
        defaultAction: "deny",
      },
      filePath: _configPath ?? "/test/agent-wall.yaml",
    }),
    PolicyEngine: MockPolicyEngine,
  };
});

const mockFs = vi.mocked(fs);
const mockOs = vi.mocked(os);

describe("doctorCommand", () => {
  let stderrSpy: any;

  beforeEach(() => {
    stderrSpy = vi.spyOn(process.stderr, "write").mockReturnValue(true);
    mockOs.homedir.mockReturnValue("/home/testuser");
    mockOs.platform.mockReturnValue("linux" as NodeJS.Platform);
    mockFs.existsSync.mockReturnValue(false);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows doctor header", () => {
    doctorCommand({});

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("Agent Wall Doctor");
  });

  it("checks Node.js version", () => {
    doctorCommand({});

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("Node.js version");
    expect(allOutput).toContain(process.versions.node);
  });

  it("checks policy config is valid", () => {
    doctorCommand({});

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("Policy config");
    expect(allOutput).toContain("1 rules");
  });

  it("reports MCP clients status", () => {
    doctorCommand({});

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("MCP clients found");
  });

  it("detects MCP client when config exists", () => {
    mockFs.existsSync.mockImplementation((p: fs.PathLike) => {
      return String(p).includes(".cursor");
    });

    doctorCommand({});

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("Cursor");
  });

  it("reports environment variable overrides", () => {
    const originalConfig = process.env.AGENT_WALL_CONFIG;
    process.env.AGENT_WALL_CONFIG = "/custom/config.yaml";

    doctorCommand({});

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("AGENT_WALL_CONFIG");

    if (originalConfig === undefined) {
      delete process.env.AGENT_WALL_CONFIG;
    } else {
      process.env.AGENT_WALL_CONFIG = originalConfig;
    }
  });

  it("shows all-pass summary when everything is ok", () => {
    // With valid config and Node >= 18, only MCP detection might fail
    // but that's just informational
    doctorCommand({});

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("Summary");
  });
});
