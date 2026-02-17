import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import { scanCommand } from "./scan.js";

vi.mock("node:fs");
vi.mock("node:os");

const mockFs = vi.mocked(fs);
const mockOs = vi.mocked(os);

describe("scanCommand", () => {
  let exitSpy: any;
  let stderrSpy: any;
  let stdoutSpy: any;

  beforeEach(() => {
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    stderrSpy = vi.spyOn(process.stderr, "write").mockReturnValue(true);
    stdoutSpy = vi.spyOn(process.stdout, "write").mockReturnValue(true);
    mockOs.homedir.mockReturnValue("/home/testuser");
    mockOs.platform.mockReturnValue("linux" as NodeJS.Platform);
    // Default: no config files found
    mockFs.existsSync.mockReturnValue(false);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows warning when no config files are found", () => {
    expect(() => scanCommand({})).toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(0);
    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("No MCP configuration files found");
  });

  it("exits with error when specified config does not exist", () => {
    expect(() =>
      scanCommand({ config: "/nonexistent/mcp.json" })
    ).toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("scans a config with risky filesystem server", () => {
    const mcpConfig = {
      mcpServers: {
        myFiles: {
          command: "npx",
          args: ["@modelcontextprotocol/server-filesystem", "/home/user"],
        },
      },
    };
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(JSON.stringify(mcpConfig));

    scanCommand({ config: "/test/mcp.json" });

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("myFiles");
    expect(allOutput).toContain("filesystem");
    expect(allOutput).toContain("Risks found");
  });

  it("detects multiple risk types in a single server", () => {
    const mcpConfig = {
      mcpServers: {
        dangerousServer: {
          command: "node",
          args: ["server-with-shell-and-filesystem.js"],
        },
      },
    };
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(JSON.stringify(mcpConfig));

    scanCommand({ config: "/test/mcp.json" });

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("shell");
    expect(allOutput).toContain("filesystem");
  });

  it("shows protected status for agent-wall wrapped servers", () => {
    const mcpConfig = {
      mcpServers: {
        secureServer: {
          command: "agent-wall",
          args: ["wrap", "--", "npx", "server-filesystem", "/path"],
        },
      },
    };
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(JSON.stringify(mcpConfig));

    scanCommand({ config: "/test/mcp.json" });

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("Protected by Agent Wall");
  });

  it("reports clean scan for safe servers", () => {
    const mcpConfig = {
      mcpServers: {
        safeServer: {
          command: "node",
          args: ["safe-read-only-server.js"],
        },
      },
    };
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(JSON.stringify(mcpConfig));

    scanCommand({ config: "/test/mcp.json" });

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("No known risks detected");
  });

  it("detects critical cloud provider risks", () => {
    const mcpConfig = {
      mcpServers: {
        cloud: {
          command: "npx",
          args: ["mcp-server-aws", "--region", "us-east-1"],
        },
      },
    };
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(JSON.stringify(mcpConfig));

    scanCommand({ config: "/test/mcp.json" });

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("CRITICAL");
    expect(allOutput).toContain("AWS");
  });

  it("handles invalid JSON config gracefully", () => {
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue("NOT_VALID_JSON{{{");

    scanCommand({ config: "/test/mcp.json" });

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("Failed to parse");
  });

  it("suggests agent-wall wrap fix for risky servers", () => {
    const mcpConfig = {
      mcpServers: {
        db: {
          command: "npx",
          args: ["mcp-server-postgres", "postgresql://localhost/mydb"],
        },
      },
    };
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(JSON.stringify(mcpConfig));

    scanCommand({ config: "/test/mcp.json" });

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("agent-wall wrap");
  });

  it("handles flat MCP config format (no mcpServers wrapper)", () => {
    const flatConfig = {
      myServer: {
        command: "npx",
        args: ["server-filesystem", "/tmp"],
      },
    };
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(JSON.stringify(flatConfig));

    scanCommand({ config: "/test/mcp.json" });

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("myServer");
  });

  it("detects Playwright browser automation risk", () => {
    const mcpConfig = {
      mcpServers: {
        browser: {
          command: "npx",
          args: ["@anthropic/mcp-server-playwright"],
        },
      },
    };
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(JSON.stringify(mcpConfig));

    scanCommand({ config: "/test/mcp.json" });

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("Playwright");
  });

  it("detects critical payment/financial risks (Stripe)", () => {
    const mcpConfig = {
      mcpServers: {
        payments: {
          command: "npx",
          args: ["@stripe/mcp-server-stripe"],
        },
      },
    };
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(JSON.stringify(mcpConfig));

    scanCommand({ config: "/test/mcp.json" });

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("CRITICAL");
    expect(allOutput).toContain("Payment");
  });

  it("detects SSH remote access as critical", () => {
    const mcpConfig = {
      mcpServers: {
        remote: {
          command: "npx",
          args: ["mcp-server-ssh", "--host", "prod.example.com"],
        },
      },
    };
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(JSON.stringify(mcpConfig));

    scanCommand({ config: "/test/mcp.json" });

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("CRITICAL");
    expect(allOutput).toContain("SSH");
  });

  it("detects GitHub MCP server as medium risk", () => {
    const mcpConfig = {
      mcpServers: {
        gh: {
          command: "npx",
          args: ["@modelcontextprotocol/server-github"],
        },
      },
    };
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(JSON.stringify(mcpConfig));

    scanCommand({ config: "/test/mcp.json" });

    const allOutput = stderrSpy.mock.calls.map((c: any) => c[0]).join("");
    expect(allOutput).toContain("GitHub");
  });

  it("outputs JSON when --json flag is set", () => {
    const mcpConfig = {
      mcpServers: {
        myDb: {
          command: "npx",
          args: ["mcp-server-postgres", "postgresql://localhost/db"],
        },
      },
    };
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(JSON.stringify(mcpConfig));

    scanCommand({ config: "/test/mcp.json", json: true });

    const jsonOut = stdoutSpy.mock.calls.map((c: any) => c[0]).join("");
    const parsed = JSON.parse(jsonOut);
    expect(parsed.servers).toHaveLength(1);
    expect(parsed.servers[0].name).toBe("myDb");
    expect(parsed.totalRisks).toBeGreaterThan(0);
  });
});
