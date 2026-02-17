/**
 * agent-wall scan — Scan your current MCP configuration for security risks.
 *
 * Reads Claude Code / Cursor MCP config files and reports
 * which servers have unrestricted access and would benefit from Agent Wall.
 *
 * Usage:
 *   agent-wall scan
 *   agent-wall scan --config ~/.claude/mcp_servers.json
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import chalk from "chalk";

export interface ScanOptions {
  config?: string;
  json?: boolean;
}

interface McpServerConfig {
  command: string;
  args?: string[];
  env?: Record<string, string>;
}

/**
 * Known risky MCP tool patterns based on the official MCP servers ecosystem.
 * Sources: modelcontextprotocol/servers registry + popular third-party servers.
 */
const RISKY_TOOLS = [
  // ── Execution (Critical) ──────────────────────────────────────────
  { pattern: "shell", risk: "critical", reason: "Arbitrary shell command execution" },
  { pattern: "bash", risk: "critical", reason: "Arbitrary bash execution" },
  { pattern: "exec", risk: "critical", reason: "Process execution" },
  { pattern: "terminal", risk: "critical", reason: "Terminal access" },

  // ── Filesystem ────────────────────────────────────────────────────
  { pattern: "filesystem", risk: "high", reason: "Full filesystem read/write access" },

  // ── Browser / Web ─────────────────────────────────────────────────
  { pattern: "playwright", risk: "high", reason: "Browser automation via Playwright (prompt injection target)" },
  { pattern: "puppeteer", risk: "high", reason: "Browser automation via Puppeteer (prompt injection target)" },
  { pattern: "browser", risk: "high", reason: "Browser automation (prompt injection target)" },
  { pattern: "fetch", risk: "medium", reason: "Outbound HTTP requests (exfiltration vector)" },

  // ── Source Control ────────────────────────────────────────────────
  { pattern: "github", risk: "medium", reason: "GitHub API access (code/issues/PRs)" },
  { pattern: "gitlab", risk: "medium", reason: "GitLab API access (code/issues/MRs)" },
  { pattern: "git", risk: "medium", reason: "Repository access and modification" },

  // ── Databases ─────────────────────────────────────────────────────
  { pattern: "postgres", risk: "high", reason: "PostgreSQL access" },
  { pattern: "mysql", risk: "high", reason: "MySQL database access" },
  { pattern: "mongodb", risk: "high", reason: "MongoDB database access" },
  { pattern: "redis", risk: "medium", reason: "Redis data store access" },
  { pattern: "sqlite", risk: "medium", reason: "SQLite database access" },
  { pattern: "supabase", risk: "high", reason: "Supabase database/auth/storage access" },
  { pattern: "neon", risk: "high", reason: "Neon serverless Postgres access" },
  { pattern: "snowflake", risk: "high", reason: "Snowflake data warehouse access" },
  { pattern: "database", risk: "high", reason: "Database query execution" },

  // ── Infrastructure / Cloud ────────────────────────────────────────
  { pattern: "docker", risk: "critical", reason: "Container management" },
  { pattern: "kubernetes", risk: "critical", reason: "Cluster management" },
  { pattern: "terraform", risk: "critical", reason: "Infrastructure-as-code provisioning" },
  { pattern: "aws", risk: "critical", reason: "AWS cloud resource access" },
  { pattern: "gcp", risk: "critical", reason: "Google Cloud resource access" },
  { pattern: "azure", risk: "critical", reason: "Azure cloud resource access" },
  { pattern: "cloudflare", risk: "high", reason: "Cloudflare infrastructure management" },
  { pattern: "vercel", risk: "high", reason: "Vercel deployment/project management" },
  { pattern: "netlify", risk: "high", reason: "Netlify deployment/project management" },

  // ── Communication ─────────────────────────────────────────────────
  { pattern: "slack", risk: "medium", reason: "Slack workspace messaging access" },
  { pattern: "email", risk: "medium", reason: "Email send/read access" },
  { pattern: "gmail", risk: "medium", reason: "Gmail account access" },
  { pattern: "discord", risk: "medium", reason: "Discord messaging access" },

  // ── Payment / Secrets ─────────────────────────────────────────────
  { pattern: "stripe", risk: "critical", reason: "Payment processing / financial data" },
  { pattern: "razorpay", risk: "critical", reason: "Payment processing / financial data" },
  { pattern: "vault", risk: "critical", reason: "Secret management (HashiCorp Vault)" },
  { pattern: "1password", risk: "critical", reason: "Password manager access" },

  // ── Remote Access ─────────────────────────────────────────────────
  { pattern: "ssh", risk: "critical", reason: "Remote server access via SSH" },
  { pattern: "rdp", risk: "critical", reason: "Remote desktop access" },

  // ── AI / LLM ──────────────────────────────────────────────────────
  { pattern: "openai", risk: "medium", reason: "OpenAI API access (cost / data)" },
  { pattern: "anthropic", risk: "medium", reason: "Anthropic API access (cost / data)" },
];

function detectConfigPaths(): string[] {
  const home = os.homedir();
  const platform = os.platform();
  const candidates: string[] = [
    // ── Claude ────────────────────────────────────────────────────
    // Claude Code
    path.join(home, ".claude", "mcp_servers.json"),
    // Claude Desktop (macOS)
    path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
    // Claude Desktop (Windows)
    path.join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json"),
    // Claude Desktop (Linux)
    path.join(home, ".config", "Claude", "claude_desktop_config.json"),

    // ── Cursor ────────────────────────────────────────────────────
    path.join(home, ".cursor", "mcp.json"),

    // ── VS Code / Copilot ─────────────────────────────────────────
    // VS Code workspace-level MCP (vscode 1.99+)
    path.join(process.cwd(), ".vscode", "mcp.json"),

    // ── Windsurf (Codeium) ────────────────────────────────────────
    path.join(home, ".codeium", "windsurf", "mcp_config.json"),

    // ── Cline ─────────────────────────────────────────────────────
    path.join(home, ".cline", "mcp_settings.json"),

    // ── Continue.dev ──────────────────────────────────────────────
    path.join(home, ".continue", "config.json"),

    // ── Generic / project-level ───────────────────────────────────
    path.join(process.cwd(), ".mcp.json"),
    path.join(process.cwd(), "mcp.json"),
  ];

  // VS Code user-level settings (platform-aware)
  if (platform === "win32") {
    candidates.push(
      path.join(home, "AppData", "Roaming", "Code", "User", "settings.json")
    );
  } else if (platform === "darwin") {
    candidates.push(
      path.join(home, "Library", "Application Support", "Code", "User", "settings.json")
    );
  } else {
    candidates.push(
      path.join(home, ".config", "Code", "User", "settings.json")
    );
  }

  return candidates.filter((p) => fs.existsSync(p));
}

export function scanCommand(options: ScanOptions): void {
  let configPaths: string[] = [];

  if (options.config) {
    if (!fs.existsSync(options.config)) {
      process.stderr.write(
        chalk.red(`Error: Config not found: ${options.config}\n`)
      );
      process.exit(1);
    }
    configPaths = [options.config];
  } else {
    configPaths = detectConfigPaths();
  }

  if (configPaths.length === 0) {
    if (options.json) {
      process.stdout.write(JSON.stringify({ servers: [], totalRisks: 0 }, null, 2) + "\n");
    } else {
      process.stderr.write(
        chalk.yellow(
          "\n⚠  No MCP configuration files found.\n\n" +
          chalk.gray(
            "  Looked for config files from:\n" +
            "    • Claude Code      ~/.claude/mcp_servers.json\n" +
            "    • Claude Desktop   ~/Library/.../claude_desktop_config.json\n" +
            "    • Cursor           ~/.cursor/mcp.json\n" +
            "    • VS Code / Copilot .vscode/mcp.json\n" +
            "    • Windsurf         ~/.codeium/windsurf/mcp_config.json\n" +
            "    • Cline            ~/.cline/mcp_settings.json\n" +
            "    • Continue.dev     ~/.continue/config.json\n" +
            "    • Project-level    .mcp.json, mcp.json\n\n" +
            "  Tip: pass --config <path> to scan a specific file.\n\n"
          )
        )
      );
    }
    process.exit(0);
  }

  // ── Collect results ──────────────────────────────────────────────
  interface ServerResult {
    name: string;
    configFile: string;
    command: string;
    protected: boolean;
    risks: Array<{ level: string; reason: string }>;
  }

  const results: ServerResult[] = [];
  let totalRisks = 0;

  for (const configPath of configPaths) {
    let raw: Record<string, unknown>;
    try {
      const content = fs.readFileSync(configPath, "utf-8");
      raw = JSON.parse(content);
    } catch {
      if (!options.json) {
        process.stderr.write(
          chalk.red(`  Failed to parse: ${configPath}\n\n`)
        );
      }
      continue;
    }

    const servers: Record<string, McpServerConfig> =
      (raw.mcpServers as Record<string, McpServerConfig>) ??
      (raw as Record<string, McpServerConfig>);

    for (const [name, config] of Object.entries(servers)) {
      if (!config || typeof config !== "object" || !config.command) continue;

      const serverStr = `${config.command} ${(config.args ?? []).join(" ")}`;
      const risks: Array<{ level: string; reason: string }> = [];

      for (const risky of RISKY_TOOLS) {
        if (serverStr.toLowerCase().includes(risky.pattern)) {
          risks.push({ level: risky.risk, reason: risky.reason });
        }
      }

      const isProtected = serverStr.includes("agent-wall");
      if (!isProtected) totalRisks += risks.length;

      results.push({
        name,
        configFile: configPath,
        command: serverStr,
        protected: isProtected,
        risks,
      });
    }
  }

  // ── JSON output ──────────────────────────────────────────────────
  if (options.json) {
    process.stdout.write(
      JSON.stringify({ servers: results, totalRisks }, null, 2) + "\n"
    );
    return;
  }

  // ── Pretty output ────────────────────────────────────────────────
  process.stderr.write("\n");
  process.stderr.write(
    chalk.cyan("─── Agent Wall Security Scan ─────────────────────\n\n")
  );

  let lastConfig = "";
  for (const server of results) {
    if (server.configFile !== lastConfig) {
      lastConfig = server.configFile;
      process.stderr.write(
        chalk.gray("  Config: ") + chalk.white(server.configFile) + "\n\n"
      );
    }

    const riskColor =
      server.risks.some((r) => r.level === "critical")
        ? chalk.red
        : server.risks.some((r) => r.level === "high")
          ? chalk.yellow
          : server.risks.length > 0
            ? chalk.gray
            : chalk.green;

    const statusIcon = server.protected
      ? chalk.green("🛡")
      : server.risks.length > 0
        ? chalk.red("⚠")
        : chalk.green("✓");

    process.stderr.write(
      `  ${statusIcon} ${chalk.bold.white(server.name)}\n`
    );
    process.stderr.write(
      chalk.gray(`     Command: ${server.command.slice(0, 80)}\n`)
    );

    if (server.protected) {
      process.stderr.write(
        chalk.green("     Protected by Agent Wall ✓\n")
      );
    } else if (server.risks.length > 0) {
      for (const risk of server.risks) {
        process.stderr.write(
          riskColor(
            `     ${risk.level.toUpperCase()}: ${risk.reason}\n`
          )
        );
      }
      process.stderr.write(
        chalk.gray(
          `     Fix: agent-wall wrap -- ${server.command}\n`
        )
      );
    } else {
      process.stderr.write(chalk.green("     No known risks detected\n"));
    }
    process.stderr.write("\n");
  }

  // Summary
  process.stderr.write(
    chalk.cyan("─── Scan Results ───────────────────────────────\n")
  );
  process.stderr.write(
    chalk.gray("  MCP Servers: ") + chalk.white(String(results.length)) + "\n"
  );
  process.stderr.write(
    chalk.gray("  Risks found: ") +
    (totalRisks > 0
      ? chalk.red(String(totalRisks))
      : chalk.green("0")) +
    "\n"
  );
  process.stderr.write(
    chalk.cyan("─────────────────────────────────────────────────\n\n")
  );

  if (totalRisks > 0) {
    process.stderr.write(
      chalk.yellow(
        "  Run 'agent-wall init' to create a policy config,\n" +
        "  then wrap your servers with 'agent-wall wrap'.\n\n"
      )
    );
  }
}
