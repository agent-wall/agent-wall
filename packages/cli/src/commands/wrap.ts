/**
 * agent-wall wrap — The main command.
 *
 * Wraps an MCP server command, intercepting all tool calls
 * through the Agent Wall policy engine.
 *
 * Usage:
 *   agent-wall wrap -- npx @modelcontextprotocol/server-filesystem /path
 *   agent-wall wrap -c agent-wall.yaml -- node my-mcp-server.js
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { createRequire } from "node:module";
import {
  StdioProxy,
  PolicyEngine,
  AuditLogger,
  ResponseScanner,
  InjectionDetector,
  EgressControl,
  KillSwitch,
  ChainDetector,
  DashboardServer,
  loadPolicy,
  createTerminalPromptHandler,
} from "@agent-wall/core";
import chalk from "chalk";

export interface WrapOptions {
  config?: string;
  logFile?: string;
  silent?: boolean;
  dryRun?: boolean;
  dashboard?: boolean;
  dashboardPort?: number;
}

export async function wrapCommand(
  serverArgs: string[],
  options: WrapOptions
): Promise<void> {
  if (serverArgs.length === 0) {
    process.stderr.write(
      chalk.red(
        "Error: No server command specified.\n" +
        "Usage: agent-wall wrap -- <command> [args...]\n\n" +
        "Example:\n" +
        "  agent-wall wrap -- npx @modelcontextprotocol/server-filesystem /home/user\n"
      )
    );
    process.exit(1);
  }

  const command = serverArgs[0];
  const args = serverArgs.slice(1);

  // Load policy
  const { config, filePath } = loadPolicy(options.config);

  if (!options.silent) {
    process.stderr.write(
      chalk.cyan("╔══════════════════════════════════════════════════╗\n")
    );
    process.stderr.write(
      chalk.cyan("║  ") +
      chalk.bold.white("Agent Wall") +
      chalk.cyan(" — Security Firewall for AI Agents  ║\n")
    );
    process.stderr.write(
      chalk.cyan("╠══════════════════════════════════════════════════╣\n")
    );
    process.stderr.write(
      chalk.cyan("║  ") +
      chalk.gray("Policy: ") +
      chalk.white(filePath ?? "built-in defaults") +
      "\n"
    );
    process.stderr.write(
      chalk.cyan("║  ") +
      chalk.gray("Rules:  ") +
      chalk.white(`${config.rules.length} loaded`) +
      "\n"
    );
    const rspScan = config.responseScanning;
    if (rspScan?.enabled !== false) {
      process.stderr.write(
        chalk.cyan("║  ") +
        chalk.gray("Scanner:") +
        chalk.white(" response scanning ON") +
        (rspScan?.detectPII ? chalk.yellow(" +PII") : "") +
        "\n"
      );
    }
    process.stderr.write(
      chalk.cyan("║  ") +
      chalk.gray("Server: ") +
      chalk.white(`${command} ${args.join(" ")}`) +
      "\n"
    );
    process.stderr.write(
      chalk.cyan("╚══════════════════════════════════════════════════╝\n\n")
    );
  }

  // Dry-run mode: just show info and exit
  if (options.dryRun) {
    process.stderr.write(
      chalk.yellow("  --dry-run mode: preview only, server will not start\n\n")
    );
    process.stderr.write(
      chalk.gray("  Default action: ") +
      chalk.white(config.defaultAction) +
      "\n"
    );
    if (config.globalRateLimit) {
      process.stderr.write(
        chalk.gray("  Rate limit:     ") +
        chalk.white(
          `${config.globalRateLimit.maxCalls} calls / ${config.globalRateLimit.windowSeconds}s`
        ) +
        "\n"
      );
    }
    process.stderr.write(
      chalk.gray("  Rules loaded:   ") +
      chalk.white(String(config.rules.length)) +
      "\n\n"
    );

    for (let i = 0; i < config.rules.length; i++) {
      const rule = config.rules[i];
      const icon =
        rule.action === "deny"
          ? chalk.red("✗")
          : rule.action === "allow"
            ? chalk.green("✓")
            : chalk.yellow("?");
      process.stderr.write(
        `  ${icon} ${chalk.bold(rule.name ?? `rule[${i}]`)}` +
        chalk.gray(` → ${rule.action}`) +
        chalk.gray(` (tool: ${rule.tool})`) +
        "\n"
      );
    }
    process.stderr.write("\n");
    process.exit(0);
  }

  // Create engine + logger + response scanner
  const policyEngine = new PolicyEngine(config);
  const securityConfig = config.security;
  const logger = new AuditLogger({
    stdout: !options.silent,
    filePath: options.logFile,
    redact: true,
    signing: securityConfig?.signing ?? false,
    signingKey: securityConfig?.signingKey,
  });

  // Create response scanner from policy config
  const responseScanner = config.responseScanning?.enabled !== false
    ? new ResponseScanner({
      enabled: true,
      maxResponseSize: config.responseScanning?.maxResponseSize,
      oversizeAction: config.responseScanning?.oversizeAction,
      detectSecrets: config.responseScanning?.detectSecrets ?? true,
      detectPII: config.responseScanning?.detectPII ?? false,
      base64Action: config.responseScanning?.base64Action,
      maxPatterns: config.responseScanning?.maxPatterns,
      patterns: config.responseScanning?.patterns,
    })
    : undefined;

  // Create security modules from config
  const injectionDetector = new InjectionDetector(securityConfig?.injectionDetection);
  const egressControl = new EgressControl(securityConfig?.egressControl);
  const killSwitch = new KillSwitch({
    ...securityConfig?.killSwitch,
    registerSignal: true,
  });
  const chainDetector = new ChainDetector(securityConfig?.chainDetection);

  // Show security module status
  if (!options.silent) {
    const modules: string[] = [];
    if (securityConfig?.injectionDetection?.enabled !== false) modules.push("injection");
    if (securityConfig?.egressControl?.enabled !== false) modules.push("egress");
    if (securityConfig?.killSwitch?.enabled !== false) modules.push("kill-switch");
    if (securityConfig?.chainDetection?.enabled !== false) modules.push("chain");
    if (securityConfig?.signing) modules.push("signing");
    if (modules.length > 0) {
      process.stderr.write(
        chalk.cyan("║  ") +
        chalk.gray("Security:") +
        chalk.white(` ${modules.join(", ")}`) +
        "\n"
      );
    }
  }

  // Create proxy
  const proxy = new StdioProxy({
    command,
    args,
    policyEngine,
    responseScanner,
    logger,
    injectionDetector,
    egressControl,
    killSwitch,
    chainDetector,
    onPrompt: createTerminalPromptHandler(),
    onReady: () => {
      if (!options.silent) {
        process.stderr.write(
          chalk.green("✓ ") +
          chalk.gray("MCP server started. Agent Wall is protecting.\n\n")
        );
      }
    },
    onExit: (code) => {
      if (!options.silent) {
        const stats = proxy.getStats();
        process.stderr.write("\n");
        process.stderr.write(
          chalk.cyan("─── Agent Wall Session Summary ────────────────────\n")
        );
        process.stderr.write(
          chalk.gray("  Total calls:    ") +
          chalk.white(String(stats.total)) +
          "\n"
        );
        process.stderr.write(
          chalk.gray("  Forwarded:      ") +
          chalk.green(String(stats.forwarded)) +
          "\n"
        );
        process.stderr.write(
          chalk.gray("  Denied:         ") +
          chalk.red(String(stats.denied)) +
          "\n"
        );
        process.stderr.write(
          chalk.gray("  Prompted:       ") +
          chalk.yellow(String(stats.prompted)) +
          "\n"
        );
        if (stats.scanned > 0) {
          process.stderr.write(
            chalk.gray("  Responses scanned: ") +
            chalk.white(String(stats.scanned)) +
            "\n"
          );
          if (stats.responseBlocked > 0) {
            process.stderr.write(
              chalk.gray("  Resp. blocked:  ") +
              chalk.red(String(stats.responseBlocked)) +
              "\n"
            );
          }
          if (stats.responseRedacted > 0) {
            process.stderr.write(
              chalk.gray("  Resp. redacted: ") +
              chalk.yellow(String(stats.responseRedacted)) +
              "\n"
            );
          }
        }
        process.stderr.write(
          chalk.cyan("─────────────────────────────────────────────────\n")
        );
      }
      process.exit(code ?? 0);
    },
    onError: (error) => {
      process.stderr.write(
        chalk.red(`\nAgent Wall Error: ${error.message}\n`)
      );
    },
  });

  // ── Policy hot-reload ────────────────────────────────────────────
  // Watch the policy file for changes and reload without restarting.
  let policyWatcher: fs.FSWatcher | null = null;
  if (filePath) {
    try {
      let debounceTimer: ReturnType<typeof setTimeout> | null = null;
      policyWatcher = fs.watch(filePath, (eventType) => {
        if (eventType !== "change") return;
        if (debounceTimer) clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
          try {
            const { config: newConfig } = loadPolicy(filePath);
            policyEngine.updateConfig(newConfig);
            if (responseScanner && newConfig.responseScanning) {
              responseScanner.updateConfig(newConfig.responseScanning);
            }
            if (!options.silent) {
              process.stderr.write(
                chalk.green("✓ ") +
                chalk.gray("Policy reloaded from ") +
                chalk.white(filePath) +
                chalk.gray(` (${newConfig.rules.length} rules)\n`)
              );
            }
          } catch (err: unknown) {
            if (!options.silent) {
              const msg = err instanceof Error ? err.message : String(err);
              process.stderr.write(
                chalk.yellow(`⚠ Policy reload failed: ${msg}\n`)
              );
            }
          }
        }, 300); // Debounce: 300ms to handle rapid file saves
      });
    } catch {
      // File watching not available — continue without hot-reload
    }
  }

  // ── Dashboard ─────────────────────────────────────────────────────
  let dashboardServer: DashboardServer | null = null;
  if (options.dashboard || options.dashboardPort) {
    const dashboardPort = options.dashboardPort ?? 61100;
    const staticDir = resolveDashboardAssets();

    dashboardServer = new DashboardServer({
      port: dashboardPort,
      proxy,
      killSwitch,
      policyEngine,
      logger,
      staticDir,
    });

    // Wire audit logger to push entries to dashboard
    logger.setOnEntry((entry) => {
      dashboardServer!.handleAuditEntry(entry);
    });

    try {
      await dashboardServer.start();
      if (!options.silent) {
        process.stderr.write(
          chalk.cyan("║  ") +
          chalk.gray("Dashboard:") +
          chalk.white(` http://localhost:${dashboardPort}`) +
          "\n"
        );
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(
        chalk.yellow(`⚠ Dashboard failed to start: ${msg}\n`)
      );
      dashboardServer = null;
    }
  }

  // Handle process signals
  const shutdown = () => {
    if (policyWatcher) {
      policyWatcher.close();
      policyWatcher = null;
    }
    dashboardServer?.stop();
    proxy.stop();
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  // Start the proxy
  try {
    await proxy.start();
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    process.stderr.write(
      chalk.red(
        `\nFailed to start MCP server: ${msg}\n\n` +
        "Make sure the server command is correct:\n" +
        `  ${command} ${args.join(" ")}\n`
      )
    );
    process.exit(1);
  }
}

// ── Dashboard Asset Resolution ──────────────────────────────────────

function resolveDashboardAssets(): string | undefined {
  // 1. Check for bundled assets (shipped with npm package)
  const bundledDir = path.join(path.dirname(new URL(import.meta.url).pathname), "dashboard");
  if (fs.existsSync(path.join(bundledDir, "index.html"))) {
    return bundledDir;
  }

  // 2. Try to find @agent-wall/dashboard's built assets via require.resolve
  try {
    const require = createRequire(import.meta.url);
    const pkgPath = require.resolve("@agent-wall/dashboard/package.json");
    const distDir = path.join(path.dirname(pkgPath), "dist");
    if (fs.existsSync(path.join(distDir, "index.html"))) {
      return distDir;
    }
  } catch {
    // Not installed or not built
  }

  // 3. Fallback: check monorepo path
  const monorepoDist = path.resolve(
    path.dirname(new URL(import.meta.url).pathname),
    "../../dashboard/dist"
  );
  if (fs.existsSync(path.join(monorepoDist, "index.html"))) {
    return monorepoDist;
  }

  return undefined;
}
