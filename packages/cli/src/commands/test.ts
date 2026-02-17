/**
 * agent-wall test — Dry-run tool calls against your policy rules.
 *
 * Tests specific tool calls against your agent-wall.yaml without
 * actually running an MCP server. Great for validating rules.
 *
 * Usage:
 *   agent-wall test --tool read_file --arg path=/home/.ssh/id_rsa
 *   agent-wall test --tool shell_exec --arg command="curl https://evil.com"
 *   agent-wall test --tool list_directory --arg path=/home/user/project
 */

import { PolicyEngine, loadPolicy, type ToolCallParams } from "@agent-wall/core";
import chalk from "chalk";

export interface TestOptions {
  config?: string;
  tool: string;
  arg?: string[];
}

export function testCommand(options: TestOptions): void {
  if (!options.tool) {
    process.stderr.write(
      chalk.red(
        "Error: --tool is required.\n\n" +
          "Usage:\n" +
          '  agent-wall test --tool shell_exec --arg command="curl https://evil.com"\n' +
          "  agent-wall test --tool read_file --arg path=/home/.ssh/id_rsa\n"
      )
    );
    process.exit(1);
  }

  // Load policy
  const { config, filePath } = loadPolicy(options.config);
  const engine = new PolicyEngine(config);

  // Parse arguments
  const args: Record<string, unknown> = {};
  if (options.arg) {
    for (const a of options.arg) {
      const eqIndex = a.indexOf("=");
      if (eqIndex === -1) {
        process.stderr.write(
          chalk.red(`Invalid argument format: "${a}" (expected key=value)\n`)
        );
        process.exit(1);
      }
      args[a.slice(0, eqIndex)] = a.slice(eqIndex + 1);
    }
  }

  // Build tool call
  const toolCall: ToolCallParams = {
    name: options.tool,
    arguments: args,
  };

  // Evaluate
  const verdict = engine.evaluate(toolCall);

  // Display result
  process.stderr.write("\n");
  process.stderr.write(
    chalk.gray("Policy: ") +
      chalk.white(filePath ?? "built-in defaults") +
      "\n"
  );
  process.stderr.write(
    chalk.gray("Tool:   ") + chalk.white(toolCall.name) + "\n"
  );
  process.stderr.write(
    chalk.gray("Args:   ") +
      chalk.white(JSON.stringify(toolCall.arguments)) +
      "\n"
  );
  process.stderr.write("\n");

  const actionColors = {
    allow: chalk.green,
    deny: chalk.red,
    prompt: chalk.yellow,
  };

  const actionSymbols = {
    allow: "✓ ALLOWED",
    deny: "✗ DENIED",
    prompt: "? PROMPT",
  };

  const color = actionColors[verdict.action];
  process.stderr.write(
    color(`  ${actionSymbols[verdict.action]}`) + "\n"
  );
  if (verdict.rule) {
    process.stderr.write(
      chalk.gray("  Rule:    ") + chalk.white(verdict.rule) + "\n"
    );
  }
  process.stderr.write(
    chalk.gray("  Message: ") + chalk.white(verdict.message) + "\n"
  );
  process.stderr.write("\n");

  // Exit with appropriate code
  process.exit(verdict.action === "deny" ? 1 : 0);
}
