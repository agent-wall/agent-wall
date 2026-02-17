/**
 * agent-wall validate — Validate a policy configuration file.
 *
 * Checks the YAML syntax, Zod schema validation, and reports
 * any issues with your policy rules.
 *
 * Usage:
 *   agent-wall validate
 *   agent-wall validate --config ./custom-policy.yaml
 */

import { loadPolicy, PolicyEngine } from "@agent-wall/core";
import chalk from "chalk";

export interface ValidateOptions {
  config?: string;
}

export function validateCommand(options: ValidateOptions): void {
  process.stderr.write("\n");
  process.stderr.write(
    chalk.cyan("─── Agent Wall Config Validation ─────────────────\n\n")
  );

  let config;
  let filePath: string | null | undefined;

  try {
    const result = loadPolicy(options.config);
    config = result.config;
    filePath = result.filePath;
  } catch (error: any) {
    process.stderr.write(
      chalk.red("  ✗ ") + chalk.red(`Failed to load config: ${error.message}\n\n`)
    );
    process.exit(1);
  }

  process.stderr.write(
    chalk.green("  ✓ ") +
      chalk.white("Config loaded: ") +
      chalk.gray(filePath ?? "built-in defaults") +
      "\n"
  );

  // Validate version
  if (config.version !== 1) {
    process.stderr.write(
      chalk.yellow("  ⚠ ") +
        chalk.yellow(`Unknown config version: ${config.version} (expected 1)\n`)
    );
  } else {
    process.stderr.write(
      chalk.green("  ✓ ") + chalk.white("Version: 1\n")
    );
  }

  // Validate default action
  const validActions = ["allow", "deny", "prompt"];
  if (!config.defaultAction || !validActions.includes(config.defaultAction)) {
    process.stderr.write(
      chalk.red("  ✗ ") +
        chalk.red(`Invalid defaultAction: "${config.defaultAction}" (expected: allow, deny, prompt)\n`)
    );
  } else {
    process.stderr.write(
      chalk.green("  ✓ ") +
        chalk.white(`Default action: ${config.defaultAction}\n`)
    );
  }

  // Validate global rate limit
  if (config.globalRateLimit) {
    if (config.globalRateLimit.maxCalls <= 0) {
      process.stderr.write(
        chalk.yellow("  ⚠ ") +
          chalk.yellow("Global rate limit maxCalls should be > 0\n")
      );
    } else {
      process.stderr.write(
        chalk.green("  ✓ ") +
          chalk.white(
            `Global rate limit: ${config.globalRateLimit.maxCalls} calls / ${config.globalRateLimit.windowSeconds}s\n`
          )
      );
    }
  }

  // Validate rules
  process.stderr.write(
    chalk.green("  ✓ ") +
      chalk.white(`Rules: ${config.rules.length} loaded\n`)
  );

  let warnings = 0;
  let errors = 0;
  const ruleNames = new Set<string>();

  for (let i = 0; i < config.rules.length; i++) {
    const rule = config.rules[i];
    const label = rule.name ?? `rule[${i}]`;

    // Check for duplicate names
    if (rule.name) {
      if (ruleNames.has(rule.name)) {
        process.stderr.write(
          chalk.yellow("  ⚠ ") +
            chalk.yellow(`Duplicate rule name: "${rule.name}"\n`)
        );
        warnings++;
      }
      ruleNames.add(rule.name);
    } else {
      process.stderr.write(
        chalk.yellow("  ⚠ ") +
          chalk.yellow(`Rule at index ${i} has no name (recommended for audit logs)\n`)
      );
      warnings++;
    }

    // Check action validity
    if (!validActions.includes(rule.action)) {
      process.stderr.write(
        chalk.red("  ✗ ") +
          chalk.red(`${label}: invalid action "${rule.action}"\n`)
      );
      errors++;
    }

    // Check tool pattern syntax (basic validation)
    if (rule.tool && rule.tool.includes(" ")) {
      process.stderr.write(
        chalk.yellow("  ⚠ ") +
          chalk.yellow(`${label}: tool pattern contains spaces — use "|" to separate alternatives\n`)
      );
      warnings++;
    }

    // Check rate limit
    if (rule.rateLimit) {
      if (rule.rateLimit.maxCalls <= 0 || rule.rateLimit.windowSeconds <= 0) {
        process.stderr.write(
          chalk.yellow("  ⚠ ") +
            chalk.yellow(`${label}: rate limit values should be > 0\n`)
        );
        warnings++;
      }
    }
  }

  // Test that the engine initializes correctly
  try {
    new PolicyEngine(config);
    process.stderr.write(
      chalk.green("  ✓ ") + chalk.white("Policy engine: OK\n")
    );
  } catch (error: any) {
    process.stderr.write(
      chalk.red("  ✗ ") +
        chalk.red(`Policy engine failed: ${error.message}\n`)
    );
    errors++;
  }

  // Summary
  process.stderr.write("\n");
  if (errors > 0) {
    process.stderr.write(
      chalk.red(`  ${errors} error(s), ${warnings} warning(s)\n\n`)
    );
    process.exit(1);
  } else if (warnings > 0) {
    process.stderr.write(
      chalk.yellow(`  ${warnings} warning(s), 0 errors — config is valid\n\n`)
    );
  } else {
    process.stderr.write(
      chalk.green("  ✓ Config is valid — no issues found\n\n")
    );
  }
}
