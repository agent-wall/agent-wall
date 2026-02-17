/**
 * agent-wall init — Generate a starter agent-wall.yaml config.
 *
 * Usage:
 *   agent-wall init
 *   agent-wall init --path ./config/agent-wall.yaml
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { generateDefaultConfigYaml } from "@agent-wall/core";
import chalk from "chalk";

export interface InitOptions {
  path?: string;
  force?: boolean;
}

export function initCommand(options: InitOptions): void {
  const outputPath = path.resolve(options.path ?? "agent-wall.yaml");

  if (fs.existsSync(outputPath) && !options.force) {
    process.stderr.write(
      chalk.yellow(
        `\n⚠  File already exists: ${outputPath}\n` +
          "   Use --force to overwrite.\n\n"
      )
    );
    process.exit(1);
  }

  const content = generateDefaultConfigYaml();
  const dir = path.dirname(outputPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(outputPath, content, "utf-8");

  process.stderr.write(
    chalk.green("\n✓ ") +
      chalk.white("Created ") +
      chalk.bold(outputPath) +
      "\n\n" +
      chalk.gray("  Next steps:\n") +
      chalk.gray("  1. Edit the rules to fit your project\n") +
      chalk.gray("  2. Wrap your MCP server:\n\n") +
      chalk.white(
        "     agent-wall wrap -- npx @modelcontextprotocol/server-filesystem /path\n"
      ) +
      "\n"
  );
}
