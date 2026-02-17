/**
 * agent-wall audit — Display and analyze audit logs.
 *
 * Usage:
 *   agent-wall audit --log ./agent-wall.log
 *   agent-wall audit --log ./agent-wall.log --filter denied
 *   agent-wall audit --log ./agent-wall.log --last 20
 */

import * as fs from "node:fs";
import chalk from "chalk";
import type { AuditEntry } from "@agent-wall/core";

export interface AuditOptions {
  log: string;
  filter?: "allowed" | "denied" | "prompted" | "all";
  last?: number;
  json?: boolean;
}

export function auditCommand(options: AuditOptions): void {
  if (!options.log) {
    process.stderr.write(
      chalk.red(
        "Error: --log is required.\n\n" +
          "Usage:\n" +
          "  agent-wall audit --log ./agent-wall.log\n" +
          "  agent-wall audit --log ./agent-wall.log --filter denied\n"
      )
    );
    process.exit(1);
  }

  if (!fs.existsSync(options.log)) {
    process.stderr.write(
      chalk.red(`Error: Log file not found: ${options.log}\n`)
    );
    process.exit(1);
  }

  // Read and parse log entries (JSON lines format)
  const content = fs.readFileSync(options.log, "utf-8");
  const lines = content.trim().split("\n").filter(Boolean);

  let entries: AuditEntry[] = [];
  for (const line of lines) {
    try {
      entries.push(JSON.parse(line));
    } catch {
      // Skip malformed lines
    }
  }

  // Apply filters
  // Filter entries by action
  const filterAction = options.filter ?? "all";
  if (filterAction !== "all") {
    const actionMap: Record<string, string> = {
      denied: "deny",
      allowed: "allow",
      prompted: "prompt",
    };
    const targetAction = actionMap[filterAction];
    entries = entries.filter((e) => e.verdict?.action === targetAction);
  }

  // Apply --last limit
  if (options.last && options.last > 0) {
    entries = entries.slice(-options.last);
  }

  if (entries.length === 0) {
    process.stderr.write(chalk.gray("\n  No matching audit entries found.\n\n"));
    process.exit(0);
  }

  // JSON output mode
  if (options.json) {
    process.stdout.write(JSON.stringify(entries, null, 2) + "\n");
    process.exit(0);
  }

  // Pretty output
  process.stderr.write("\n");
  process.stderr.write(
    chalk.cyan("─── Agent Wall Audit Log ─────────────────────────\n")
  );
  process.stderr.write(
    chalk.gray(`  File: ${options.log}  |  Entries: ${entries.length}\n`)
  );
  process.stderr.write(
    chalk.cyan("─────────────────────────────────────────────────\n\n")
  );

  const actionColors: Record<string, (s: string) => string> = {
    allow: chalk.green,
    deny: chalk.red,
    prompt: chalk.yellow,
  };

  const actionIcons: Record<string, string> = {
    allow: "✓",
    deny: "✗",
    prompt: "?",
  };

  for (const entry of entries) {
    const action = entry.verdict?.action ?? "unknown";
    const color = actionColors[action] ?? chalk.gray;
    const icon = actionIcons[action] ?? "·";
    const time = entry.timestamp
      ? new Date(entry.timestamp).toLocaleTimeString()
      : "??:??:??";

    process.stderr.write(
      chalk.gray(`  ${time} `) +
        color(`${icon} ${(action.toUpperCase()).padEnd(6)} `) +
        chalk.white(entry.tool ?? entry.method ?? "unknown") +
        "\n"
    );

    if (entry.arguments && Object.keys(entry.arguments).length > 0) {
      const argStr = JSON.stringify(entry.arguments, null, 0);
      process.stderr.write(
        chalk.gray(`           Args: ${argStr.slice(0, 100)}${argStr.length > 100 ? "..." : ""}`) +
          "\n"
      );
    }

    if (entry.verdict?.rule) {
      process.stderr.write(
        chalk.gray(`           Rule: ${entry.verdict.rule}`) + "\n"
      );
    }
    process.stderr.write("\n");
  }

  // Summary
  const stats = {
    allowed: entries.filter((e) => e.verdict?.action === "allow").length,
    denied: entries.filter((e) => e.verdict?.action === "deny").length,
    prompted: entries.filter((e) => e.verdict?.action === "prompt").length,
  };
  process.stderr.write(
    chalk.cyan("─── Summary ────────────────────────────────────\n")
  );
  process.stderr.write(
    chalk.green(`  Allowed: ${stats.allowed}`) +
      "  " +
      chalk.red(`Denied: ${stats.denied}`) +
      "  " +
      chalk.yellow(`Prompted: ${stats.prompted}`) +
      "\n"
  );
  process.stderr.write(
    chalk.cyan("─────────────────────────────────────────────────\n\n")
  );
}
