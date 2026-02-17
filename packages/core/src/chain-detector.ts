/**
 * Agent Wall Tool Call Chain Detector
 *
 * Detects suspicious sequences of tool calls that indicate
 * multi-step attacks. Individual calls may look innocent,
 * but the CHAIN reveals the attack:
 *
 *   read_file(.env) → write_file(tmp.txt) → bash(curl)  = EXFILTRATION
 *   list_directory(/) → read_file(passwd) → read_file(shadow) = RECON
 *   write_file(script.sh) → bash(chmod +x) → bash(./script.sh) = DROPPER
 *
 * The detector maintains a sliding window of recent tool calls
 * and matches against known attack chain patterns.
 */

import type { ToolCallParams } from "./types.js";

// ── Types ───────────────────────────────────────────────────────────

export interface ChainDetectorConfig {
  /** Enable chain detection (default: true) */
  enabled?: boolean;
  /** Sliding window size (number of recent calls to track) */
  windowSize?: number;
  /** Time window in ms (calls older than this are dropped) */
  windowMs?: number;
  /** Custom chain patterns to add */
  customChains?: ChainPattern[];
}

export interface ChainPattern {
  /** Unique name for this chain pattern */
  name: string;
  /** Ordered sequence of tool name glob patterns */
  sequence: string[];
  /** Severity: "low", "medium", "high", "critical" */
  severity: "low" | "medium" | "high" | "critical";
  /** Human-readable description */
  message: string;
  /** Whether argument values must match across steps (e.g., same file read then sent) */
  trackArguments?: boolean;
}

export interface ChainDetectionResult {
  /** Whether a suspicious chain was detected */
  detected: boolean;
  /** Matched chain patterns */
  matches: ChainMatchInfo[];
  /** Human-readable summary */
  summary: string;
}

export interface ChainMatchInfo {
  /** Name of the matched chain pattern */
  chain: string;
  /** Severity level */
  severity: "low" | "medium" | "high" | "critical";
  /** The tool calls that formed the chain */
  calls: string[];
  /** Description */
  message: string;
}

// ── Built-in Chain Patterns ─────────────────────────────────────────

const BUILTIN_CHAINS: ChainPattern[] = [
  // ── Exfiltration chains ──
  {
    name: "read-then-network",
    sequence: ["read_*|get_*|view_*", "shell_*|run_*|execute_*|bash"],
    severity: "high",
    message: "Potential data exfiltration: file read followed by shell command",
  },
  {
    name: "read-write-send",
    sequence: ["read_*|get_*", "write_*|create_*", "shell_*|run_*|bash"],
    severity: "critical",
    message: "Exfiltration chain: read → write → shell (staged exfiltration)",
  },
  {
    name: "env-then-network",
    sequence: ["read_*|get_*", "shell_*|run_*|bash"],
    severity: "critical",
    message: "Potential secret exfiltration: file read followed by network command",
    trackArguments: true,
  },

  // ── Reconnaissance chains ──
  {
    name: "directory-scan",
    sequence: ["list_*|ls", "list_*|ls", "list_*|ls", "read_*|get_*"],
    severity: "medium",
    message: "Directory scanning pattern: multiple listings followed by file read",
  },

  // ── Dropper/persistence chains ──
  {
    name: "write-execute",
    sequence: ["write_*|create_*", "shell_*|run_*|bash"],
    severity: "high",
    message: "Potential dropper: file write followed by shell execution",
  },
  {
    name: "write-chmod-execute",
    sequence: ["write_*|create_*", "shell_*|run_*|bash", "shell_*|run_*|bash"],
    severity: "critical",
    message: "Dropper chain: write → chmod → execute",
  },

  // ── Privilege escalation ──
  {
    name: "read-sensitive-then-write",
    sequence: ["read_*|get_*", "write_*|create_*|edit_*"],
    severity: "medium",
    message: "Sensitive file read followed by file modification",
    trackArguments: true,
  },

  // ── Rapid shell commands ──
  {
    name: "shell-burst",
    sequence: ["shell_*|run_*|bash", "shell_*|run_*|bash", "shell_*|run_*|bash", "shell_*|run_*|bash"],
    severity: "high",
    message: "Rapid burst of shell commands — potential automated attack",
  },
];

// ── Internal tracked call ───────────────────────────────────────────

interface TrackedCall {
  tool: string;
  args: Record<string, unknown>;
  timestamp: number;
}

// ── Chain Detector ──────────────────────────────────────────────────

export class ChainDetector {
  private config: Required<ChainDetectorConfig>;
  private history: TrackedCall[] = [];
  private allChains: ChainPattern[];

  constructor(config: ChainDetectorConfig = {}) {
    this.config = {
      enabled: config.enabled ?? true,
      windowSize: config.windowSize ?? 20,
      windowMs: config.windowMs ?? 60_000, // 1 minute
      customChains: config.customChains ?? [],
    };
    this.allChains = [...BUILTIN_CHAINS, ...this.config.customChains];
  }

  /**
   * Record a tool call and check for suspicious chains.
   * Call this AFTER the policy engine allows the call.
   */
  record(toolCall: ToolCallParams): ChainDetectionResult {
    if (!this.config.enabled) {
      return { detected: false, matches: [], summary: "Chain detection disabled" };
    }

    const now = Date.now();

    // Add to history
    this.history.push({
      tool: toolCall.name,
      args: toolCall.arguments ?? {},
      timestamp: now,
    });

    // Prune old entries
    this.pruneHistory(now);

    // Check all chain patterns against current history
    const matches: ChainMatchInfo[] = [];

    for (const chain of this.allChains) {
      if (this.matchesChain(chain)) {
        matches.push({
          chain: chain.name,
          severity: chain.severity,
          calls: this.history.slice(-chain.sequence.length).map((c) => c.tool),
          message: chain.message,
        });
      }
    }

    if (matches.length === 0) {
      return { detected: false, matches: [], summary: "No suspicious chains detected" };
    }

    const highestSeverity = matches.reduce((best, m) => {
      const levels = { low: 0, medium: 1, high: 2, critical: 3 };
      return levels[m.severity] > levels[best] ? m.severity : best;
    }, "low" as "low" | "medium" | "high" | "critical");

    return {
      detected: true,
      matches,
      summary: `Suspicious tool call chain detected (${highestSeverity}): ${matches.map((m) => m.chain).join(", ")}`,
    };
  }

  /**
   * Check if the current history matches a chain pattern.
   * Looks for the sequence appearing in order (not necessarily consecutive).
   */
  private matchesChain(chain: ChainPattern): boolean {
    if (this.history.length < chain.sequence.length) return false;

    // Check the most recent N calls match the sequence in order
    const recentCalls = this.history.slice(-chain.sequence.length);

    for (let i = 0; i < chain.sequence.length; i++) {
      const pattern = chain.sequence[i];
      const call = recentCalls[i];
      if (!this.matchesToolPattern(pattern, call.tool)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Match a tool name against a pipe-separated glob-like pattern.
   */
  private matchesToolPattern(pattern: string, toolName: string): boolean {
    const alternatives = pattern.split("|").map((p) => p.trim());
    return alternatives.some((p) => {
      if (p === "*") return true;
      if (p.endsWith("*")) {
        return toolName.startsWith(p.slice(0, -1));
      }
      if (p.startsWith("*")) {
        return toolName.endsWith(p.slice(1));
      }
      return toolName === p;
    });
  }

  /**
   * Remove entries outside the time window or exceeding window size.
   */
  private pruneHistory(now: number): void {
    // Remove by time
    const cutoff = now - this.config.windowMs;
    this.history = this.history.filter((c) => c.timestamp >= cutoff);

    // Remove by size (keep most recent)
    if (this.history.length > this.config.windowSize) {
      this.history = this.history.slice(-this.config.windowSize);
    }
  }

  /**
   * Clear the call history (e.g., on session reset).
   */
  reset(): void {
    this.history = [];
  }

  /**
   * Get the current call history length.
   */
  getHistoryLength(): number {
    return this.history.length;
  }
}
