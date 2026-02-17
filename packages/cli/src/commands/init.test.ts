import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { initCommand } from "./init.js";

vi.mock("node:fs");
vi.mock("@agent-wall/core", () => ({
  generateDefaultConfigYaml: () =>
    "version: 1\ndefaultAction: deny\nrules: []\n",
}));

const mockFs = vi.mocked(fs);

describe("initCommand", () => {
  let exitSpy: any;
  let stderrSpy: any;

  beforeEach(() => {
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    stderrSpy = vi.spyOn(process.stderr, "write").mockReturnValue(true);
    mockFs.existsSync.mockReturnValue(false);
    mockFs.writeFileSync.mockReturnValue(undefined);
    mockFs.mkdirSync.mockReturnValue(undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("creates a new config file at default path", () => {
    initCommand({});
    expect(mockFs.writeFileSync).toHaveBeenCalledWith(
      expect.stringContaining("agent-wall.yaml"),
      expect.stringContaining("version: 1"),
      "utf-8"
    );
  });

  it("creates config at custom path", () => {
    initCommand({ path: "./custom/policy.yaml" });
    expect(mockFs.writeFileSync).toHaveBeenCalledWith(
      expect.stringContaining("policy.yaml"),
      expect.any(String),
      "utf-8"
    );
  });

  it("exits with error when file exists and no --force", () => {
    mockFs.existsSync.mockReturnValue(true);
    expect(() => initCommand({})).toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(stderrSpy).toHaveBeenCalledWith(
      expect.stringContaining("already exists")
    );
  });

  it("overwrites when --force is used", () => {
    mockFs.existsSync.mockImplementation((p) => {
      // File exists, but force overwrite
      return String(p).endsWith("agent-wall.yaml");
    });
    initCommand({ force: true });
    expect(mockFs.writeFileSync).toHaveBeenCalled();
  });

  it("creates parent directory recursively", () => {
    // First existsSync check: file doesn't exist; second: dir doesn't exist
    mockFs.existsSync.mockReturnValue(false);
    initCommand({ path: "./deep/nested/config.yaml" });
    expect(mockFs.mkdirSync).toHaveBeenCalledWith(
      expect.any(String),
      { recursive: true }
    );
  });

  it("prints success message with next steps", () => {
    initCommand({});
    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("Created");
    expect(allOutput).toContain("Next steps");
    expect(allOutput).toContain("agent-wall wrap");
  });
});
