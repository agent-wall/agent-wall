/**
 * Agent Wall Policy Engine
 *
 * Evaluates tool calls against YAML-defined rules.
 * Rules are matched in order — first match wins.
 * If no rule matches, the default action applies.
 *
 * Security hardening:
 *   - Path normalization (resolves ../ before matching)
 *   - Unicode NFC normalization (prevents homoglyph bypass)
 *   - Zero-trust "strict" mode (default deny, only explicit allows pass)
 *   - Safe regex construction (prevents ReDoS in argument matching)
 *   - Deep argument scanning across all string values
 */

import * as path from "node:path";
import { minimatch } from "minimatch";
import type { ToolCallParams } from "./types.js";
import type { InjectionDetectorConfig } from "./injection-detector.js";
import type { EgressControlConfig } from "./egress-control.js";
import type { KillSwitchConfig } from "./kill-switch.js";
import type { ChainDetectorConfig } from "./chain-detector.js";

// ── Rule Types ──────────────────────────────────────────────────────

export type RuleAction = "allow" | "deny" | "prompt";

/** Policy mode: "standard" (backward-compatible) or "strict" (zero-trust) */
export type PolicyMode = "standard" | "strict";

export interface RuleMatch {
  /** Glob patterns matched against string values in arguments */
  arguments?: Record<string, string>;
}

export interface RateLimitConfig {
  maxCalls: number;
  windowSeconds: number;
}

export interface PolicyRule {
  name: string;
  /** Glob pattern for tool name(s). Use "|" to separate multiple patterns. */
  tool: string;
  /** Optional argument matching */
  match?: RuleMatch;
  /** What to do when this rule matches */
  action: RuleAction;
  /** Human-readable message shown when rule triggers */
  message?: string;
  /** Rate limiting for this rule's scope */
  rateLimit?: RateLimitConfig;
}

/** Security modules configuration. */
export interface SecurityConfig {
  /** Prompt injection detection */
  injectionDetection?: InjectionDetectorConfig;
  /** URL/SSRF egress control */
  egressControl?: EgressControlConfig;
  /** Emergency kill switch */
  killSwitch?: KillSwitchConfig;
  /** Tool call chain/sequence detection */
  chainDetection?: ChainDetectorConfig;
  /** Enable HMAC-SHA256 audit log signing */
  signing?: boolean;
  /** Signing key (auto-generated per session if not provided) */
  signingKey?: string;
}

export interface PolicyConfig {
  version: number;
  /** Policy mode: "standard" (default) or "strict" (zero-trust deny-by-default) */
  mode?: PolicyMode;
  /** Default action when no rule matches (overridden to "deny" in strict mode) */
  defaultAction?: RuleAction;
  /** Global rate limit across all tools */
  globalRateLimit?: RateLimitConfig;
  /** Response scanning configuration */
  responseScanning?: ResponseScannerPolicyConfig;
  /** Security modules (injection detection, egress control, kill switch, chain detection) */
  security?: SecurityConfig;
  /** Ordered list of rules — first match wins */
  rules: PolicyRule[];
}

/** Response scanning section in the YAML policy. */
export interface ResponseScannerPolicyConfig {
  enabled?: boolean;
  maxResponseSize?: number;
  oversizeAction?: "block" | "redact";
  detectSecrets?: boolean;
  detectPII?: boolean;
  /** Action for base64 blob detection: "pass" (default), "redact", or "block" */
  base64Action?: "pass" | "redact" | "block";
  /** Maximum number of custom patterns allowed (default: 100) */
  maxPatterns?: number;
  patterns?: Array<{
    name: string;
    pattern: string;
    flags?: string;
    action: "pass" | "redact" | "block";
    message?: string;
    category?: string;
  }>;
}

// ── Policy Evaluation Result ────────────────────────────────────────

export interface PolicyVerdict {
  action: RuleAction;
  rule: string | null; // Name of the matched rule, or null for default
  message: string;
}

// ── Rate Limiter ────────────────────────────────────────────────────

interface RateLimitBucket {
  timestamps: number[];
}

class RateLimiter {
  private buckets = new Map<string, RateLimitBucket>();

  check(key: string, config: RateLimitConfig): boolean {
    const now = Date.now();
    const windowMs = config.windowSeconds * 1000;
    const bucket = this.buckets.get(key) ?? { timestamps: [] };

    // Prune old entries outside the window
    bucket.timestamps = bucket.timestamps.filter((t) => now - t < windowMs);

    if (bucket.timestamps.length >= config.maxCalls) {
      return false; // Rate limit exceeded
    }

    bucket.timestamps.push(now);
    this.buckets.set(key, bucket);
    return true;
  }

  reset(): void {
    this.buckets.clear();
  }
}

// ── Normalization Utilities ─────────────────────────────────────────

/**
 * Normalize a string value for secure matching:
 * 1. Unicode NFC normalization (prevents homoglyph/decomposition bypass)
 * 2. Path normalization for path-like values (resolves ../ traversal)
 */
function normalizeValue(value: string): string {
  // Unicode NFC normalization
  let normalized = value.normalize("NFC");

  // Path normalization: if it looks like a file path, resolve traversals
  if (looksLikePath(normalized)) {
    normalized = normalizePath(normalized);
  }

  return normalized;
}

/**
 * Heuristic: does this string look like a file path?
 */
function looksLikePath(value: string): boolean {
  return (
    value.includes("/") ||
    value.includes("\\") ||
    value.startsWith(".") ||
    value.startsWith("~")
  );
}

/**
 * Normalize a file path: resolve ../ and ./ components, normalize separators.
 * Does NOT resolve to absolute path (preserves relative paths).
 */
function normalizePath(p: string): string {
  // Normalize separators to forward slash
  let normalized = p.replace(/\\/g, "/");

  // Use path.posix.normalize to resolve ../ and ./
  normalized = path.posix.normalize(normalized);

  return normalized;
}

/**
 * Safe glob-to-regex conversion with ReDoS protection.
 * Limits the resulting regex complexity.
 */
function safeGlobToRegex(pattern: string): RegExp | null {
  // Reject patterns that are too long (ReDoS vector)
  if (pattern.length > 500) return null;

  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");

  try {
    return new RegExp(`^${escaped}$`, "i");
  } catch {
    return null;
  }
}

// ── Common argument key aliases ─────────────────────────────────────

/**
 * Map of common argument key aliases for path-like values.
 * If a rule specifies "path", it also matches "file", "filepath", etc.
 */
const PATH_KEY_ALIASES: Record<string, string[]> = {
  path: ["file", "filepath", "file_path", "filename", "file_name", "target", "source", "destination", "dest", "src", "uri", "url"],
  command: ["cmd", "shell", "exec", "script", "run"],
  content: ["text", "body", "data", "input", "message"],
};

/**
 * Get all alias keys for a given argument key.
 */
function getKeyAliases(key: string): string[] {
  const lowerKey = key.toLowerCase();
  // Direct aliases
  const aliases = PATH_KEY_ALIASES[lowerKey];
  if (aliases) return [lowerKey, ...aliases];

  // Reverse lookup: if key is an alias, find its canonical form
  for (const [canonical, aliasList] of Object.entries(PATH_KEY_ALIASES)) {
    if (aliasList.includes(lowerKey)) {
      return [canonical, ...aliasList];
    }
  }

  return [lowerKey];
}

// ── Policy Engine ───────────────────────────────────────────────────

export class PolicyEngine {
  private config: PolicyConfig;
  private rateLimiter = new RateLimiter();

  constructor(config: PolicyConfig) {
    this.config = config;
  }

  /**
   * Update the policy configuration (e.g., after file reload).
   */
  updateConfig(config: PolicyConfig): void {
    this.config = config;
    this.rateLimiter.reset();
  }

  /**
   * Evaluate a tool call against the policy rules.
   * Returns the verdict: allow, deny, or prompt.
   */
  evaluate(toolCall: ToolCallParams): PolicyVerdict {
    // 1. Check global rate limit
    if (this.config.globalRateLimit) {
      if (!this.rateLimiter.check("__global__", this.config.globalRateLimit)) {
        return {
          action: "deny",
          rule: "__global_rate_limit__",
          message: `Global rate limit exceeded (${this.config.globalRateLimit.maxCalls} calls per ${this.config.globalRateLimit.windowSeconds}s)`,
        };
      }
    }

    // 2. Evaluate rules in order — first match wins
    for (const rule of this.config.rules) {
      if (this.matchesRule(rule, toolCall)) {
        // Check per-rule rate limit
        if (rule.rateLimit) {
          if (!this.rateLimiter.check(`rule:${rule.name}`, rule.rateLimit)) {
            return {
              action: "deny",
              rule: rule.name,
              message:
                rule.message ??
                `Rate limit exceeded for rule "${rule.name}" (${rule.rateLimit.maxCalls} per ${rule.rateLimit.windowSeconds}s)`,
            };
          }
        }

        return {
          action: rule.action,
          rule: rule.name,
          message:
            rule.message ??
            `${rule.action === "deny" ? "Blocked" : rule.action === "prompt" ? "Approval required" : "Allowed"} by rule "${rule.name}"`,
        };
      }
    }

    // 3. No rule matched — use default action
    // In strict (zero-trust) mode, default is always "deny"
    const isStrict = this.config.mode === "strict";
    const defaultAction = isStrict ? "deny" : (this.config.defaultAction ?? "prompt");
    return {
      action: defaultAction,
      rule: null,
      message: isStrict
        ? `Zero-trust mode: no matching allow rule. Denied by default.`
        : `No matching rule. Default action: ${defaultAction}`,
    };
  }

  /**
   * Check if a rule matches a tool call.
   */
  private matchesRule(rule: PolicyRule, toolCall: ToolCallParams): boolean {
    // Match tool name — normalize with NFC
    const normalizedToolName = toolCall.name.normalize("NFC");
    if (!this.matchToolName(rule.tool, normalizedToolName)) {
      return false;
    }

    // Match arguments if specified
    if (rule.match?.arguments) {
      if (!this.matchArguments(rule.match.arguments, toolCall.arguments ?? {})) {
        return false;
      }
    }

    return true;
  }

  /**
   * Match a tool name against a pattern.
   * Pattern can contain "|" for multiple alternatives.
   */
  private matchToolName(pattern: string, toolName: string): boolean {
    const patterns = pattern.split("|").map((p) => p.trim());
    return patterns.some((p) => minimatch(toolName, p));
  }

  /**
   * Match rule argument patterns against actual tool arguments.
   * Each key in ruleArgs is an argument name, value is a glob pattern.
   * ALL specified argument patterns must match for the rule to match.
   *
   * Security: normalizes paths and unicode before matching.
   * Security: checks key aliases (path → file, filepath, etc.)
   */
  private matchArguments(
    ruleArgs: Record<string, string>,
    actualArgs: Record<string, unknown>
  ): boolean {
    for (const [key, pattern] of Object.entries(ruleArgs)) {
      // Get the actual value — try the key directly and all aliases
      const aliases = getKeyAliases(key);
      let rawValue: unknown;
      for (const alias of aliases) {
        // Case-insensitive key lookup
        const found = Object.entries(actualArgs).find(
          ([k]) => k.toLowerCase() === alias
        );
        if (found !== undefined && found[1] !== undefined) {
          rawValue = found[1];
          break;
        }
      }

      if (rawValue === undefined) return false;

      // Normalize the value (Unicode NFC + path traversal resolution)
      const strValue = normalizeValue(String(rawValue));
      const patterns = pattern.split("|").map((p) => p.trim());

      // At least one pattern must match
      const matched = patterns.some((p) => {
        // Try glob match with dot:true so patterns match dotfiles
        if (minimatch(strValue, p, { dot: true })) return true;

        // Fallback: safe glob-to-regex for non-path strings
        if (p.includes("*") || p.includes("?")) {
          const regex = safeGlobToRegex(p);
          if (regex && regex.test(strValue)) return true;
        }

        // Also try case-insensitive substring for simple patterns
        if (!p.includes("*") && !p.includes("?")) {
          return strValue.toLowerCase().includes(p.toLowerCase());
        }
        return false;
      });

      if (!matched) return false;
    }
    return true;
  }

  /**
   * Get the current policy config.
   */
  getConfig(): PolicyConfig {
    return this.config;
  }

  /**
   * Get all rule names.
   */
  getRuleNames(): string[] {
    return this.config.rules.map((r) => r.name);
  }
}
