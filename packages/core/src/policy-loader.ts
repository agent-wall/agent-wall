/**
 * Agent Wall Policy Loader
 *
 * Loads and validates policy configuration from YAML files.
 * Supports loading from a specific path or auto-discovering
 * agent-wall.yaml in the current directory or parent directories.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as yaml from "js-yaml";
import { z } from "zod";
import type { PolicyConfig, PolicyRule, RuleAction, SecurityConfig } from "./policy-engine.js";

// ── YAML Schema Validation ──────────────────────────────────────────

const RateLimitSchema = z.object({
  maxCalls: z.number().int().positive(),
  windowSeconds: z.number().positive(),
});

const RuleMatchSchema = z.object({
  arguments: z.record(z.string()).optional(),
});

const PolicyRuleSchema = z.object({
  name: z.string().min(1),
  tool: z.string().min(1),
  match: RuleMatchSchema.optional(),
  action: z.enum(["allow", "deny", "prompt"]),
  message: z.string().optional(),
  rateLimit: RateLimitSchema.optional(),
});

const ResponsePatternSchema = z.object({
  name: z.string().min(1),
  pattern: z.string().min(1),
  flags: z.string().optional(),
  action: z.enum(["pass", "redact", "block"]),
  message: z.string().optional(),
  category: z.string().optional(),
});

const ResponseScanningSchema = z.object({
  enabled: z.boolean().optional(),
  maxResponseSize: z.number().int().nonnegative().optional(),
  oversizeAction: z.enum(["block", "redact"]).optional(),
  detectSecrets: z.boolean().optional(),
  detectPII: z.boolean().optional(),
  base64Action: z.enum(["pass", "redact", "block"]).optional(),
  maxPatterns: z.number().int().positive().optional(),
  patterns: z.array(ResponsePatternSchema).optional(),
});

// ── Security Config Schemas ──────────────────────────────────────────

const InjectionDetectionSchema = z.object({
  enabled: z.boolean().optional(),
  sensitivity: z.enum(["low", "medium", "high"]).optional(),
  customPatterns: z.array(z.string()).optional(),
  excludeTools: z.array(z.string()).optional(),
});

const EgressControlSchema = z.object({
  enabled: z.boolean().optional(),
  allowedDomains: z.array(z.string()).optional(),
  blockedDomains: z.array(z.string()).optional(),
  blockPrivateIPs: z.boolean().optional(),
  blockMetadataEndpoints: z.boolean().optional(),
  excludeTools: z.array(z.string()).optional(),
});

const KillSwitchSchema = z.object({
  enabled: z.boolean().optional(),
  checkFile: z.boolean().optional(),
  killFileNames: z.array(z.string()).optional(),
  pollIntervalMs: z.number().int().positive().optional(),
});

const ChainDetectionSchema = z.object({
  enabled: z.boolean().optional(),
  windowSize: z.number().int().positive().optional(),
  windowMs: z.number().int().positive().optional(),
});

const SecuritySchema = z.object({
  injectionDetection: InjectionDetectionSchema.optional(),
  egressControl: EgressControlSchema.optional(),
  killSwitch: KillSwitchSchema.optional(),
  chainDetection: ChainDetectionSchema.optional(),
  signing: z.boolean().optional(),
  signingKey: z.string().optional(),
});

const PolicyConfigSchema = z.object({
  version: z.number().int().min(1),
  mode: z.enum(["standard", "strict"]).optional(),
  defaultAction: z.enum(["allow", "deny", "prompt"]).optional(),
  globalRateLimit: RateLimitSchema.optional(),
  responseScanning: ResponseScanningSchema.optional(),
  security: SecuritySchema.optional(),
  rules: z.array(PolicyRuleSchema),
});

// ── Config File Names ───────────────────────────────────────────────

const CONFIG_FILENAMES = [
  "agent-wall.yaml",
  "agent-wall.yml",
  ".agent-wall.yaml",
  ".agent-wall.yml",
  // Legacy support

];

// ── Loader Functions ────────────────────────────────────────────────

/**
 * Load a policy config from a specific file path.
 */
export function loadPolicyFile(filePath: string): PolicyConfig {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Policy file not found: ${filePath}`);
  }

  const content = fs.readFileSync(filePath, "utf-8");
  return parsePolicyYaml(content);
}

/**
 * Parse a YAML string into a validated PolicyConfig.
 */
export function parsePolicyYaml(yamlContent: string): PolicyConfig {
  const raw = yaml.load(yamlContent, { schema: yaml.JSON_SCHEMA });
  const validated = PolicyConfigSchema.parse(raw);
  return validated as PolicyConfig;
}

/**
 * Auto-discover the nearest agent-wall.yaml by walking up
 * from the given directory (defaults to cwd).
 * Returns the file path if found, null otherwise.
 */
export function discoverPolicyFile(
  startDir: string = process.cwd()
): string | null {
  let dir = path.resolve(startDir);

  while (true) {
    for (const filename of CONFIG_FILENAMES) {
      const candidate = path.join(dir, filename);
      if (fs.existsSync(candidate)) {
        return candidate;
      }
    }

    const parent = path.dirname(dir);
    if (parent === dir) break; // Reached filesystem root
    dir = parent;
  }

  return null;
}

/**
 * Load the policy config by auto-discovering the config file.
 * Falls back to default policy if no config file found.
 */
export function loadPolicy(configPath?: string): {
  config: PolicyConfig;
  filePath: string | null;
} {
  if (configPath) {
    return {
      config: loadPolicyFile(configPath),
      filePath: configPath,
    };
  }

  const discovered = discoverPolicyFile();
  if (discovered) {
    return {
      config: loadPolicyFile(discovered),
      filePath: discovered,
    };
  }

  // No config found — return sensible defaults
  return {
    config: getDefaultPolicy(),
    filePath: null,
  };
}

/**
 * Get the default policy config.
 * Ships with Agent Wall — provides reasonable security out of the box.
 */
export function getDefaultPolicy(): PolicyConfig {
  return {
    version: 1,
    defaultAction: "prompt",
    globalRateLimit: {
      maxCalls: 200,
      windowSeconds: 60,
    },
    responseScanning: {
      enabled: true,
      maxResponseSize: 5 * 1024 * 1024, // 5MB
      oversizeAction: "redact",
      detectSecrets: true,
      detectPII: false,
    },
    security: {
      injectionDetection: { enabled: true, sensitivity: "medium" },
      egressControl: { enabled: true, blockPrivateIPs: true, blockMetadataEndpoints: true },
      killSwitch: { enabled: true, checkFile: true },
      chainDetection: { enabled: true },
      signing: false,
    },
    rules: [
      // ── Always block: credential access ──
      {
        name: "block-ssh-keys",
        tool: "*",
        match: { arguments: { path: "**/.ssh/**|**/.ssh" } },
        action: "deny" as RuleAction,
        message: "Access to SSH keys is blocked by default policy",
      },
      {
        name: "block-env-files",
        tool: "*",
        match: { arguments: { path: "**/.env*" } },
        action: "deny" as RuleAction,
        message: "Access to .env files is blocked by default policy",
      },
      {
        name: "block-credential-files",
        tool: "*",
        match: {
          arguments: { path: "*credentials*|**/*.pem|**/*.key|**/*.pfx|**/*.p12" },
        },
        action: "deny" as RuleAction,
        message: "Access to credential files is blocked by default policy",
      },
      // ── Always block: exfiltration patterns ──
      {
        name: "block-curl-exfil",
        tool: "shell_exec|run_command|execute_command",
        match: { arguments: { command: "*curl *" } },
        action: "deny" as RuleAction,
        message:
          "Shell commands with curl are blocked — potential data exfiltration",
      },
      {
        name: "block-wget-exfil",
        tool: "shell_exec|run_command|execute_command",
        match: { arguments: { command: "*wget *" } },
        action: "deny" as RuleAction,
        message:
          "Shell commands with wget are blocked — potential data exfiltration",
      },
      {
        name: "block-netcat-exfil",
        tool: "shell_exec|run_command|execute_command",
        match: { arguments: { command: "*nc *|*ncat *|*netcat *" } },
        action: "deny" as RuleAction,
        message:
          "Shell commands with netcat are blocked — potential data exfiltration",
      },
      {
        name: "block-powershell-exfil",
        tool: "shell_exec|run_command|execute_command|bash",
        match: { arguments: { command: "*powershell*|*pwsh*|*Invoke-WebRequest*|*Invoke-RestMethod*|*DownloadString*|*DownloadFile*|*Start-BitsTransfer*" } },
        action: "deny" as RuleAction,
        message:
          "PowerShell command blocked — potential data exfiltration",
      },
      {
        name: "block-dns-exfil",
        tool: "shell_exec|run_command|execute_command|bash",
        match: { arguments: { command: "*nslookup *|*dig *|*host *" } },
        action: "deny" as RuleAction,
        message:
          "DNS lookup command blocked — potential DNS exfiltration vector",
      },
      // ── Require approval: scripting language one-liners ──
      {
        name: "approve-script-exec",
        tool: "shell_exec|run_command|execute_command|bash",
        match: { arguments: { command: "*python* -c *|*python3* -c *|*ruby* -e *|*perl* -e *|*node* -e *|*node* --eval*" } },
        action: "prompt" as RuleAction,
        message:
          "Inline script execution requires approval — may be used for exfiltration",
      },
      // ── Require approval: destructive operations ──
      {
        name: "approve-file-delete",
        tool: "*delete*|*remove*|*unlink*",
        action: "prompt" as RuleAction,
        message: "File deletion requires approval",
      },
      {
        name: "approve-shell-exec",
        tool: "shell_exec|run_command|execute_command|bash",
        action: "prompt" as RuleAction,
        message: "Shell command execution requires approval",
      },
      // ── Allow: safe read operations ──
      {
        name: "allow-read-file",
        tool: "read_file|get_file_contents|view_file",
        action: "allow" as RuleAction,
      },
      {
        name: "allow-list-dir",
        tool: "list_directory|list_dir|ls",
        action: "allow" as RuleAction,
      },
      {
        name: "allow-search",
        tool: "search_files|grep|find_files|ripgrep",
        action: "allow" as RuleAction,
      },
    ],
  };
}

/**
 * Generate the default agent-wall.yaml content for `agent-wall init`.
 */
export function generateDefaultConfigYaml(): string {
  return `# Agent Wall Policy Configuration
# Docs: https://github.com/agent-wall/agent-wall
#
# Rules are evaluated in order — first match wins.
# Actions: allow, deny, prompt (ask human for approval)

version: 1

# Default action when no rule matches
defaultAction: prompt

# Global rate limit across all tools
globalRateLimit:
  maxCalls: 200
  windowSeconds: 60

# Response scanning — inspect what the MCP server returns
# before it reaches the AI agent
responseScanning:
  enabled: true
  maxResponseSize: 5242880  # 5MB
  oversizeAction: redact    # "block" or "redact" (truncate)
  detectSecrets: true       # API keys, tokens, private keys
  detectPII: false          # Email, phone, SSN, credit cards (opt-in)
  # Custom patterns (optional):
  # patterns:
  #   - name: internal-urls
  #     pattern: "https?://internal\\.[a-z]+\\.corp"
  #     action: redact
  #     message: "Internal URL detected"
  #     category: custom

# Security modules
security:
  injectionDetection:
    enabled: true
    sensitivity: medium      # low, medium, high
  egressControl:
    enabled: true
    blockPrivateIPs: true    # Block RFC1918, loopback, link-local IPs
    blockMetadataEndpoints: true  # Block cloud metadata (169.254.169.254)
  killSwitch:
    enabled: true
    checkFile: true          # Watch for .agent-wall-kill file
  chainDetection:
    enabled: true            # Detect exfiltration chains (read→curl, etc.)
  signing: false             # HMAC-SHA256 audit log signing

rules:
  # ── Block: Credential Access ────────────────────────────
  - name: block-ssh-keys
    tool: "*"
    match:
      arguments:
        path: "**/.ssh/**|**/.ssh"
    action: deny
    message: "Access to SSH keys is blocked"

  - name: block-env-files
    tool: "*"
    match:
      arguments:
        path: "**/.env*"
    action: deny
    message: "Access to .env files is blocked"

  - name: block-credential-files
    tool: "*"
    match:
      arguments:
        path: "*credentials*|**/*.pem|**/*.key|**/*.pfx|**/*.p12"
    action: deny
    message: "Access to credential files is blocked"

  # ── Block: Exfiltration Patterns ────────────────────────
  - name: block-curl-exfil
    tool: "shell_exec|run_command|execute_command"
    match:
      arguments:
        command: "*curl *"
    action: deny
    message: "Shell commands with curl are blocked (potential exfiltration)"

  - name: block-wget-exfil
    tool: "shell_exec|run_command|execute_command"
    match:
      arguments:
        command: "*wget *"
    action: deny
    message: "Shell commands with wget are blocked (potential exfiltration)"

  - name: block-netcat-exfil
    tool: "shell_exec|run_command|execute_command"
    match:
      arguments:
        command: "*nc *|*ncat *|*netcat *"
    action: deny
    message: "Shell commands with netcat are blocked (potential exfiltration)"

  - name: block-powershell-exfil
    tool: "shell_exec|run_command|execute_command|bash"
    match:
      arguments:
        command: "*powershell*|*pwsh*|*Invoke-WebRequest*|*Invoke-RestMethod*|*DownloadString*|*DownloadFile*|*Start-BitsTransfer*"
    action: deny
    message: "PowerShell command blocked (potential exfiltration)"

  - name: block-dns-exfil
    tool: "shell_exec|run_command|execute_command|bash"
    match:
      arguments:
        command: "*nslookup *|*dig *|*host *"
    action: deny
    message: "DNS lookup blocked (potential DNS exfiltration)"

  # ── Prompt: Scripting One-Liners ────────────────────
  - name: approve-script-exec
    tool: "shell_exec|run_command|execute_command|bash"
    match:
      arguments:
        command: "*python* -c *|*python3* -c *|*ruby* -e *|*perl* -e *|*node* -e *|*node* --eval*"
    action: prompt
    message: "Inline script execution requires approval"

  # ── Prompt: Destructive Operations ──────────────────────
  - name: approve-file-delete
    tool: "*delete*|*remove*|*unlink*"
    action: prompt
    message: "File deletion requires approval"

  - name: approve-shell-exec
    tool: "shell_exec|run_command|execute_command|bash"
    action: prompt
    message: "Shell command execution requires approval"

  # ── Allow: Safe Read Operations ─────────────────────────
  - name: allow-read-file
    tool: "read_file|get_file_contents|view_file"
    action: allow

  - name: allow-list-dir
    tool: "list_directory|list_dir|ls"
    action: allow

  - name: allow-search
    tool: "search_files|grep|find_files|ripgrep"
    action: allow

  # ────────────────────────────────────────────────────────
  # Add your own rules below. Remember: first match wins!
  # ────────────────────────────────────────────────────────
`;
}
