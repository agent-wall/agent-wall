import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import { auditCommand } from "./audit.js";
import type { AuditEntry } from "@agent-wall/core";

vi.mock("node:fs");

const mockFs = vi.mocked(fs);

function makeEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    timestamp: "2026-01-15T10:30:00.000Z",
    sessionId: "test-session-1",
    direction: "request",
    method: "tools/call",
    tool: "read_file",
    arguments: { path: "/home/user/file.txt" },
    verdict: { action: "allow", rule: "allow-reads", message: "Matched rule" },
    ...overrides,
  };
}

function makeLogContent(entries: AuditEntry[]): string {
  return entries.map((e) => JSON.stringify(e)).join("\n");
}

describe("auditCommand", () => {
  let exitSpy: any;
  let stderrSpy: any;
  let stdoutSpy: any;

  beforeEach(() => {
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    stderrSpy = vi.spyOn(process.stderr, "write").mockReturnValue(true);
    stdoutSpy = vi.spyOn(process.stdout, "write").mockReturnValue(true);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("exits with error when --log is missing", () => {
    expect(() =>
      auditCommand({ log: "" })
    ).toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("exits with error when log file does not exist", () => {
    mockFs.existsSync.mockReturnValue(false);
    expect(() =>
      auditCommand({ log: "./nonexistent.log" })
    ).toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("not found");
  });

  it("displays audit entries in pretty format", () => {
    const entries = [
      makeEntry(),
      makeEntry({
        tool: "shell_exec",
        verdict: { action: "deny", rule: "block-shell", message: "Blocked" },
      }),
    ];
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(makeLogContent(entries));

    auditCommand({ log: "./test.log" });

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("Audit Log");
    expect(allOutput).toContain("read_file");
    expect(allOutput).toContain("shell_exec");
    expect(allOutput).toContain("Summary");
  });

  it("filters by denied entries", () => {
    const entries = [
      makeEntry({ tool: "read_file", verdict: { action: "allow", rule: null, message: "" } }),
      makeEntry({
        tool: "shell_exec",
        verdict: { action: "deny", rule: "block-shell", message: "Blocked" },
      }),
      makeEntry({
        tool: "write_file",
        verdict: { action: "deny", rule: "block-writes", message: "Blocked" },
      }),
    ];
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(makeLogContent(entries));

    auditCommand({ log: "./test.log", filter: "denied" });

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    // Should show 2 denied entries, not the allowed one
    expect(allOutput).toContain("Entries: 2");
  });

  it("applies --last limit", () => {
    const entries = Array.from({ length: 10 }, (_, i) =>
      makeEntry({ tool: `tool_${i}` })
    );
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(makeLogContent(entries));

    auditCommand({ log: "./test.log", last: 3 });

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("Entries: 3");
  });

  it("outputs JSON when --json flag is set", () => {
    const entries = [makeEntry()];
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(makeLogContent(entries));

    expect(() =>
      auditCommand({ log: "./test.log", json: true })
    ).toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(0);

    const jsonOutput = stdoutSpy.mock.calls.map((c: any) => c[0]).join("");
    const parsed = JSON.parse(jsonOutput);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed[0].tool).toBe("read_file");
  });

  it("shows empty state when no entries match filter", () => {
    const entries = [
      makeEntry({ verdict: { action: "allow", rule: null, message: "" } }),
    ];
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(makeLogContent(entries));

    expect(() =>
      auditCommand({ log: "./test.log", filter: "denied" })
    ).toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(0);
    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("No matching");
  });

  it("skips malformed JSON lines gracefully", () => {
    const content = `${JSON.stringify(makeEntry())}\nINVALID_JSON\n${JSON.stringify(makeEntry({ tool: "write_file" }))}`;
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(content);

    auditCommand({ log: "./test.log" });

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("Entries: 2"); // Skips the invalid line
  });

  it("shows summary counts correctly", () => {
    const entries = [
      makeEntry({ verdict: { action: "allow", rule: null, message: "" } }),
      makeEntry({ verdict: { action: "allow", rule: null, message: "" } }),
      makeEntry({ verdict: { action: "deny", rule: "x", message: "" } }),
      makeEntry({ verdict: { action: "prompt", rule: "y", message: "" } }),
    ];
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(makeLogContent(entries));

    auditCommand({ log: "./test.log" });

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("Allowed: 2");
    expect(allOutput).toContain("Denied: 1");
    expect(allOutput).toContain("Prompted: 1");
  });
});
