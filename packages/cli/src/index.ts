/**
 * Agent Wall CLI
 *
 * Security firewall for AI agents.
 * Intercepts MCP tool calls, enforces policies, blocks attacks.
 *
 * Commands:
 *   wrap      — Wrap an MCP server with Agent Wall protection
 *   init      — Generate a starter agent-wall.yaml config
 *   test      — Dry-run a tool call against your policy rules
 *   audit     — Display and analyze audit logs
 *   scan      — Scan your MCP config for security risks
 *   validate  — Validate your policy configuration file
 */

import { Command } from "commander";
import { wrapCommand } from "./commands/wrap.js";
import { initCommand } from "./commands/init.js";
import { testCommand } from "./commands/test.js";
import { auditCommand } from "./commands/audit.js";
import { scanCommand } from "./commands/scan.js";
import { validateCommand } from "./commands/validate.js";
import { doctorCommand } from "./commands/doctor.js";

/** Resolve env-var fallback for config path. */
function envConfig(explicit?: string): string | undefined {
  return explicit ?? process.env.AGENT_WALL_CONFIG ?? undefined;
}

/** Resolve env-var fallback for log file path. */
function envLogFile(explicit?: string): string | undefined {
  return explicit ?? process.env.AGENT_WALL_LOG ?? undefined;
}

const program = new Command();

program
  .name("agent-wall")
  .description(
    "Security firewall for AI agents — intercept MCP tool calls, enforce policies, block attacks."
  )
  .version("0.1.1");

// ── wrap ─────────────────────────────────────────────────────────────

program
  .command("wrap")
  .description("Wrap an MCP server with Agent Wall policy enforcement")
  .option("-c, --config <path>", "Path to agent-wall.yaml config file")
  .option("-l, --log-file <path>", "Path to write audit log (JSON lines)")
  .option("-s, --silent", "Suppress Agent Wall output (only MCP protocol on stdout)")
  .option("--dry-run", "Preview policy evaluation without starting the server")
  .option("-d, --dashboard", "Launch real-time security dashboard")
  .option("--dashboard-port <port>", "Dashboard port (default: 61100)", parseInt)
  .argument("[serverArgs...]", "Server command and arguments (after --)")
  .allowUnknownOption(true)
  .action((serverArgs: string[], opts) => {
    wrapCommand(serverArgs, {
      config: envConfig(opts.config),
      logFile: envLogFile(opts.logFile),
      silent: opts.silent,
      dryRun: opts.dryRun,
      dashboard: opts.dashboard,
      dashboardPort: opts.dashboardPort,
    });
  });

// ── init ─────────────────────────────────────────────────────────────

program
  .command("init")
  .description("Generate a starter agent-wall.yaml configuration file")
  .option("-p, --path <path>", "Output path (default: ./agent-wall.yaml)")
  .option("-f, --force", "Overwrite existing file")
  .action((opts) => {
    initCommand({ path: opts.path, force: opts.force });
  });

// ── test ─────────────────────────────────────────────────────────────

program
  .command("test")
  .description("Dry-run a tool call against your policy rules")
  .option("-c, --config <path>", "Path to agent-wall.yaml config file")
  .requiredOption("-t, --tool <name>", "Tool name to test")
  .option(
    "-a, --arg <key=value>",
    "Tool argument (repeatable)",
    (val: string, prev: string[]) => [...prev, val],
    [] as string[]
  )
  .action((opts) => {
    testCommand({ config: envConfig(opts.config), tool: opts.tool, arg: opts.arg });
  });

// ── audit ────────────────────────────────────────────────────────────

program
  .command("audit")
  .description("Display and analyze audit logs")
  .requiredOption("-l, --log <path>", "Path to the audit log file")
  .option(
    "-f, --filter <action>",
    "Filter by action: allowed, denied, prompted, all",
    "all"
  )
  .option("-n, --last <count>", "Show only the last N entries", parseInt)
  .option("--json", "Output raw JSON")
  .action((opts) => {
    auditCommand({
      log: opts.log,
      filter: opts.filter,
      last: opts.last,
      json: opts.json,
    });
  });

// ── scan ─────────────────────────────────────────────────────────────

program
  .command("scan")
  .description("Scan your MCP configuration for security risks")
  .option("-c, --config <path>", "Path to MCP config file")
  .option("--json", "Output results as JSON")
  .action((opts) => {
    scanCommand({ config: opts.config, json: opts.json });
  });

// ── validate ─────────────────────────────────────────────────────────

program
  .command("validate")
  .description("Validate your policy configuration file")
  .option("-c, --config <path>", "Path to agent-wall.yaml config file")
  .action((opts) => {
    validateCommand({ config: envConfig(opts.config) });
  });

// ── doctor ───────────────────────────────────────────────────────────

program
  .command("doctor")
  .description("Health check — verify config, environment, and MCP setup")
  .option("-c, --config <path>", "Path to agent-wall.yaml config file")
  .action((opts) => {
    doctorCommand({ config: envConfig(opts.config) });
  });

// ── Parse ────────────────────────────────────────────────────────────

program.parse();
