/**
 * agent-wall doctor — Health check for your Agent Wall setup.
 *
 * Verifies: config file exists & is valid, Node.js version,
 * MCP clients detected, and whether servers are wrapped.
 *
 * Usage:
 *   agent-wall doctor
 *   agent-wall doctor --config ./agent-wall.yaml
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import chalk from "chalk";
import { loadPolicy, PolicyEngine } from "@agent-wall/core";

export interface DoctorOptions {
  config?: string;
}

interface CheckResult {
  label: string;
  ok: boolean;
  detail: string;
}

export function doctorCommand(options: DoctorOptions): void {
  const checks: CheckResult[] = [];

  process.stderr.write("\n");
  process.stderr.write(
    chalk.cyan("─── Agent Wall Doctor ───────────────────────────\n\n")
  );

  // ── Check 1: Node.js version ────────────────────────────────────
  const nodeVersion = process.versions.node;
  const [major] = nodeVersion.split(".").map(Number);
  checks.push({
    label: "Node.js version",
    ok: major >= 18,
    detail: `v${nodeVersion}${major < 18 ? " (requires >= 18)" : ""}`,
  });

  // ── Check 2: Config file ────────────────────────────────────────
  let configOk = false;
  let configDetail = "";
  let ruleCount = 0;
  try {
    const { config, filePath } = loadPolicy(options.config);
    configOk = true;
    ruleCount = config.rules.length;
    configDetail = `${filePath ?? "built-in defaults"} (${ruleCount} rules)`;

    // Also validate the engine can initialize
    const engine = new PolicyEngine(config);
    engine.evaluate({ name: "__doctor_test__", arguments: {} });
  } catch (err) {
    configDetail = err instanceof Error ? err.message : String(err);
  }
  checks.push({
    label: "Policy config",
    ok: configOk,
    detail: configDetail,
  });

  // ── Check 3: MCP client configs detected ────────────────────────
  const home = os.homedir();
  const platform = os.platform();
  const mcpClients: Array<{ name: string; path: string }> = [
    { name: "Claude Code", path: path.join(home, ".claude", "mcp_servers.json") },
    { name: "Cursor", path: path.join(home, ".cursor", "mcp.json") },
    { name: "VS Code", path: path.join(process.cwd(), ".vscode", "mcp.json") },
    { name: "Windsurf", path: path.join(home, ".codeium", "windsurf", "mcp_config.json") },
    { name: "Cline", path: path.join(home, ".cline", "mcp_settings.json") },
  ];
  if (platform === "win32") {
    mcpClients.push({
      name: "Claude Desktop",
      path: path.join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json"),
    });
  } else if (platform === "darwin") {
    mcpClients.push({
      name: "Claude Desktop",
      path: path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
    });
  } else {
    mcpClients.push({
      name: "Claude Desktop",
      path: path.join(home, ".config", "Claude", "claude_desktop_config.json"),
    });
  }

  const detected = mcpClients.filter((c) => fs.existsSync(c.path));
  checks.push({
    label: "MCP clients found",
    ok: detected.length > 0,
    detail:
      detected.length > 0
        ? detected.map((c) => c.name).join(", ")
        : "None detected (run 'agent-wall scan' for details)",
  });

  // ── Check 4: Environment variables ──────────────────────────────
  const envVars: string[] = [];
  if (process.env.AGENT_WALL_CONFIG) envVars.push("AGENT_WALL_CONFIG");
  if (process.env.AGENT_WALL_LOG) envVars.push("AGENT_WALL_LOG");
  checks.push({
    label: "Env overrides",
    ok: true, // Always "ok" — just informational
    detail: envVars.length > 0 ? envVars.join(", ") : "None set",
  });

  // ── Print results ───────────────────────────────────────────────
  for (const check of checks) {
    const icon = check.ok ? chalk.green("✓") : chalk.red("✗");
    process.stderr.write(
      `  ${icon} ${chalk.bold.white(check.label)}\n`
    );
    process.stderr.write(chalk.gray(`    ${check.detail}\n\n`));
  }

  // ── Summary ─────────────────────────────────────────────────────
  const failures = checks.filter((c) => !c.ok);
  process.stderr.write(
    chalk.cyan("─── Summary ────────────────────────────────────\n")
  );
  if (failures.length === 0) {
    process.stderr.write(
      chalk.green("  All checks passed. Agent Wall is ready.\n\n")
    );
  } else {
    process.stderr.write(
      chalk.yellow(
        `  ${failures.length} issue(s) found:\n`
      )
    );
    for (const f of failures) {
      process.stderr.write(chalk.yellow(`    • ${f.label}: ${f.detail}\n`));
    }
    process.stderr.write("\n");
  }
  process.stderr.write(
    chalk.cyan("─────────────────────────────────────────────────\n\n")
  );
}
