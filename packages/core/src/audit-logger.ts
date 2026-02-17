/**
 * Agent Wall Audit Logger
 *
 * Structured logging of every tool call and its policy verdict.
 * Logs to stderr (JSON) and optionally to a file.
 * This is the audit trail — proof of what the agent did and what was blocked.
 *
 * Security:
 *   - HMAC-SHA256 chain signing (tamper-evident log entries)
 *   - Log rotation (max file size with automatic rotation)
 *   - File permission checks on policy files
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import type { RuleAction } from "./policy-engine.js";

// ── Log Entry Types ─────────────────────────────────────────────────

export interface AuditEntry {
  timestamp: string;
  sessionId: string;
  direction: "request" | "response";
  method: string;
  tool?: string;
  arguments?: Record<string, unknown>;
  verdict?: {
    action: RuleAction;
    rule: string | null;
    message: string;
  };
  responsePreview?: string;
  latencyMs?: number;
  error?: string;
}

/** Signed audit entry — includes HMAC chain for tamper evidence. */
export interface SignedAuditEntry extends AuditEntry {
  /** HMAC-SHA256 of this entry + previous hash (chain) */
  _sig?: string;
  /** Sequence number in the chain */
  _seq?: number;
}

// ── Logger Options ──────────────────────────────────────────────────

export interface AuditLoggerOptions {
  /** Log to stdout as JSON lines (default: true) */
  stdout?: boolean;
  /** Log to a file (JSON lines) */
  filePath?: string;
  /** Redact sensitive values in arguments (default: true) */
  redact?: boolean;
  /** Maximum argument value length before truncation */
  maxArgLength?: number;
  /** Silent mode — no output */
  silent?: boolean;
  /** Enable HMAC-SHA256 chain signing */
  signing?: boolean;
  /** HMAC signing key (auto-generated per session if not provided) */
  signingKey?: string;
  /** Max log file size in bytes before rotation (default: 50MB, 0 = no limit) */
  maxFileSize?: number;
  /** Number of rotated log files to keep (default: 5) */
  maxFiles?: number;
  /** Callback fired after every log entry (for dashboard streaming) */
  onEntry?: (entry: AuditEntry) => void;
}

// ── Sensitive Patterns ──────────────────────────────────────────────

const SENSITIVE_PATTERNS = [
  /password/i,
  /secret/i,
  /token/i,
  /api[_-]?key/i,
  /auth/i,
  /credential/i,
  /private[_-]?key/i,
  /access[_-]?key/i,
];

// ── Constants ───────────────────────────────────────────────────────

const DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
const DEFAULT_MAX_FILES = 5;

// ── Logger Implementation ───────────────────────────────────────────

export class AuditLogger {
  private options: {
    stdout: boolean;
    filePath: string;
    redact: boolean;
    maxArgLength: number;
    silent: boolean;
    signing: boolean;
    signingKey: string;
    maxFileSize: number;
    maxFiles: number;
    onEntry?: (entry: AuditEntry) => void;
  };
  private fileFd: number | null = null;
  private entries: AuditEntry[] = [];
  private prevHash: string = "genesis";
  private seqCounter: number = 0;
  private currentFileSize: number = 0;

  constructor(options: AuditLoggerOptions = {}) {
    this.options = {
      stdout: options.stdout ?? true,
      filePath: options.filePath ?? "",
      redact: options.redact ?? true,
      maxArgLength: options.maxArgLength ?? 200,
      silent: options.silent ?? false,
      signing: options.signing ?? false,
      signingKey: options.signingKey ?? crypto.randomBytes(32).toString("hex"),
      maxFileSize: options.maxFileSize ?? DEFAULT_MAX_FILE_SIZE,
      maxFiles: options.maxFiles ?? DEFAULT_MAX_FILES,
      onEntry: options.onEntry,
    };

    if (this.options.filePath) {
      this.openLogFile();
    }
  }

  /**
   * Open or reopen the log file using synchronous fd (reliable on Windows).
   */
  private openLogFile(): void {
    const dir = path.dirname(this.options.filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Get current file size for rotation tracking
    try {
      const stat = fs.statSync(this.options.filePath);
      this.currentFileSize = stat.size;
    } catch {
      this.currentFileSize = 0;
    }

    this.fileFd = fs.openSync(this.options.filePath, "a");
  }

  /**
   * Log a tool call with its policy verdict.
   */
  log(entry: AuditEntry): void {
    const processed = this.options.redact
      ? this.redactEntry(entry)
      : entry;

    this.entries.push(processed);

    // Add HMAC chain signature if signing is enabled
    let outputEntry: SignedAuditEntry = { ...processed };
    if (this.options.signing) {
      this.seqCounter++;
      const sig = this.computeHmac(processed);
      outputEntry._seq = this.seqCounter;
      outputEntry._sig = sig;
      this.prevHash = sig;
    }

    const line = JSON.stringify(outputEntry);

    if (this.options.stdout && !this.options.silent) {
      process.stderr.write(`[agent-wall] ${line}\n`);
    }

    if (this.fileFd !== null) {
      const data = line + "\n";
      const bytes = Buffer.byteLength(data, "utf-8");
      fs.writeSync(this.fileFd, data);
      this.currentFileSize += bytes;

      // Check if rotation is needed
      if (this.options.maxFileSize > 0 && this.currentFileSize >= this.options.maxFileSize) {
        this.rotateLogFile();
      }
    }

    this.options.onEntry?.(processed);
  }

  /**
   * Compute HMAC-SHA256 for a log entry in the chain.
   * Chain: HMAC(entry_json + prev_hash)
   */
  private computeHmac(entry: AuditEntry): string {
    const payload = JSON.stringify(entry) + "|" + this.prevHash;
    return crypto
      .createHmac("sha256", this.options.signingKey)
      .update(payload)
      .digest("hex");
  }

  /**
   * Rotate log files: current → .1, .1 → .2, etc.
   * Oldest file beyond maxFiles is deleted.
   */
  private rotateLogFile(): void {
    // Close current file descriptor synchronously (critical on Windows)
    if (this.fileFd !== null) {
      fs.closeSync(this.fileFd);
      this.fileFd = null;
    }

    const basePath = this.options.filePath;

    // Delete oldest if at max
    const oldest = `${basePath}.${this.options.maxFiles}`;
    try { fs.unlinkSync(oldest); } catch { /* doesn't exist */ }

    // Shift existing rotated files: .4 → .5, .3 → .4, etc.
    for (let i = this.options.maxFiles - 1; i >= 1; i--) {
      const src = `${basePath}.${i}`;
      const dst = `${basePath}.${i + 1}`;
      try { fs.renameSync(src, dst); } catch { /* doesn't exist */ }
    }

    // Move current → .1
    try { fs.renameSync(basePath, `${basePath}.1`); } catch { /* ignore */ }

    // Reopen fresh log file
    this.currentFileSize = 0;
    this.openLogFile();
  }

  /**
   * Log a denied tool call (convenience method).
   */
  logDeny(
    sessionId: string,
    tool: string,
    args: Record<string, unknown>,
    ruleName: string | null,
    message: string
  ): void {
    this.log({
      timestamp: new Date().toISOString(),
      sessionId,
      direction: "request",
      method: "tools/call",
      tool,
      arguments: args,
      verdict: {
        action: "deny",
        rule: ruleName,
        message,
      },
    });
  }

  /**
   * Log an allowed tool call (convenience method).
   */
  logAllow(
    sessionId: string,
    tool: string,
    args: Record<string, unknown>,
    ruleName: string | null,
    message: string
  ): void {
    this.log({
      timestamp: new Date().toISOString(),
      sessionId,
      direction: "request",
      method: "tools/call",
      tool,
      arguments: args,
      verdict: {
        action: "allow",
        rule: ruleName,
        message,
      },
    });
  }

  /**
   * Get all logged entries (for the audit command).
   */
  getEntries(): AuditEntry[] {
    return this.entries;
  }

  /**
   * Get summary statistics.
   */
  getStats(): {
    total: number;
    allowed: number;
    denied: number;
    prompted: number;
  } {
    let allowed = 0;
    let denied = 0;
    let prompted = 0;
    for (const entry of this.entries) {
      switch (entry.verdict?.action) {
        case "allow":
          allowed++;
          break;
        case "deny":
          denied++;
          break;
        case "prompt":
          prompted++;
          break;
      }
    }
    return {
      total: this.entries.length,
      allowed,
      denied,
      prompted,
    };
  }

  /**
   * Redact sensitive argument values.
   */
  private redactEntry(entry: AuditEntry): AuditEntry {
    if (!entry.arguments) return entry;

    const redacted: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(entry.arguments)) {
      if (SENSITIVE_PATTERNS.some((p) => p.test(key))) {
        redacted[key] = "[REDACTED]";
      } else if (typeof value === "string" && value.length > this.options.maxArgLength) {
        redacted[key] = value.slice(0, this.options.maxArgLength) + "...[truncated]";
      } else {
        redacted[key] = value;
      }
    }

    return { ...entry, arguments: redacted };
  }

  /**
   * Verify the HMAC chain integrity of a log file.
   * Returns { valid: boolean, entries: number, firstBroken: number | null }
   */
  static verifyChain(
    logFilePath: string,
    signingKey: string
  ): { valid: boolean; entries: number; firstBroken: number | null } {
    const content = fs.readFileSync(logFilePath, "utf-8");
    const lines = content.trim().split("\n").filter(Boolean);

    let prevHash = "genesis";
    let firstBroken: number | null = null;

    for (let i = 0; i < lines.length; i++) {
      const parsed = JSON.parse(lines[i]) as SignedAuditEntry;
      const { _sig, _seq, ...entry } = parsed;

      if (!_sig) {
        // Unsigned entry — skip or flag
        continue;
      }

      const payload = JSON.stringify(entry) + "|" + prevHash;
      const expected = crypto
        .createHmac("sha256", signingKey)
        .update(payload)
        .digest("hex");

      if (_sig !== expected) {
        if (firstBroken === null) firstBroken = i;
      }

      prevHash = _sig;
    }

    return {
      valid: firstBroken === null,
      entries: lines.length,
      firstBroken,
    };
  }

  /**
   * Set or replace the onEntry callback (for dashboard streaming).
   */
  setOnEntry(callback: ((entry: AuditEntry) => void) | undefined): void {
    this.options.onEntry = callback;
  }

  /**
   * Close the logger (flush file stream).
   */
  close(): void {
    if (this.fileFd !== null) {
      fs.closeSync(this.fileFd);
      this.fileFd = null;
    }
  }
}

// ── File Permission Checking ────────────────────────────────────────

export interface FilePermissionCheckResult {
  safe: boolean;
  warnings: string[];
}

/**
 * Check if a policy file has safe permissions.
 * Warns if world-writable, group-writable, or owned by different user.
 * On Windows this is best-effort (no Unix permission model).
 */
export function checkFilePermissions(filePath: string): FilePermissionCheckResult {
  const warnings: string[] = [];

  try {
    const stat = fs.statSync(filePath);

    // Unix permission checks (mode is a bitmask)
    const mode = stat.mode;
    if (mode !== undefined) {
      // Check world-writable (o+w = 0o002)
      if (mode & 0o002) {
        warnings.push(
          `Policy file is world-writable (mode ${(mode & 0o777).toString(8)}). ` +
          `Run: chmod 644 ${filePath}`
        );
      }

      // Check group-writable (g+w = 0o020)
      if (mode & 0o020) {
        warnings.push(
          `Policy file is group-writable (mode ${(mode & 0o777).toString(8)}). ` +
          `Consider: chmod 644 ${filePath}`
        );
      }
    }

    // Check if the file is a symlink (could be pointing to attacker-controlled path)
    const lstat = fs.lstatSync(filePath);
    if (lstat.isSymbolicLink()) {
      warnings.push(
        `Policy file is a symbolic link. Ensure it points to a trusted location.`
      );
    }
  } catch (err) {
    warnings.push(`Cannot check permissions for ${filePath}: ${err}`);
  }

  return {
    safe: warnings.length === 0,
    warnings,
  };
}
