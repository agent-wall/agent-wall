/**
 * Agent Wall Response Scanner
 *
 * Inspects MCP server responses BEFORE they reach the AI agent.
 * This is the second half of the firewall:
 *   - Policy Engine controls what goes IN  (tool calls)
 *   - Response Scanner controls what comes OUT (tool results)
 *
 * Detects:
 *   1. Secret leaks (API keys, tokens, passwords in response text)
 *   2. Data exfiltration markers (base64 blobs, large hex dumps)
 *   3. Sensitive file content (private keys, certificates, AWS creds)
 *   4. Oversized responses (context window stuffing)
 *   5. Custom patterns (user-defined via YAML config)
 *
 * Security:
 *   - ReDoS-safe pattern validation (rejects dangerous regex)
 *   - Max pattern count enforcement
 *   - Configurable base64 blob action
 *   - Generic redaction markers (no pattern name leak)
 */

// ── Types ───────────────────────────────────────────────────────────

export type ResponseAction = "pass" | "redact" | "block";

/** A single pattern to match against response content. */
export interface ResponsePattern {
  /** Unique name for this pattern */
  name: string;
  /** Regex pattern to match against response text */
  pattern: string;
  /** Flags for the regex (default: "gi") */
  flags?: string;
  /** What to do when the pattern matches */
  action: ResponseAction;
  /** Human-readable description */
  message?: string;
  /** Category for grouping in audit logs */
  category?: string;
}

/** Configuration for response scanning. */
export interface ResponseScannerConfig {
  /** Enable/disable the response scanner (default: true) */
  enabled?: boolean;
  /** Maximum response size in bytes before blocking (0 = no limit) */
  maxResponseSize?: number;
  /** Action when response exceeds maxResponseSize: "block" or "redact" (truncate) */
  oversizeAction?: "block" | "redact";
  /** Built-in secret detection (default: true) */
  detectSecrets?: boolean;
  /** Built-in PII detection (default: false — opt-in) */
  detectPII?: boolean;
  /** Action for base64 blob detection: "pass" (default), "redact", or "block" */
  base64Action?: ResponseAction;
  /** Maximum number of custom patterns allowed (default: 100) */
  maxPatterns?: number;
  /** Custom patterns to match against response content */
  patterns?: ResponsePattern[];
}

/** Result of scanning a response. */
export interface ScanResult {
  /** Whether the response is clean */
  clean: boolean;
  /** The final action to take */
  action: ResponseAction;
  /** All findings */
  findings: ScanFinding[];
  /** If action is "redact", the redacted response text */
  redactedText?: string;
  /** Original size in bytes */
  originalSize: number;
}

/** A single finding from the scanner. */
export interface ScanFinding {
  /** Name of the pattern that matched */
  pattern: string;
  /** Category */
  category: string;
  /** The action this pattern requests */
  action: ResponseAction;
  /** Human-readable message */
  message: string;
  /** Number of matches found */
  matchCount: number;
  /** Preview of matched content (redacted) */
  preview?: string;
}

// ── ReDoS Protection ────────────────────────────────────────────────

/**
 * Dangerous regex patterns that indicate potential ReDoS:
 * - Nested quantifiers: (a+)+ , (a*)*
 * - Overlapping alternations with quantifiers
 */
const REDOS_DANGEROUS_PATTERNS = [
  /\([^)]*[+*][^)]*\)[+*]/,    // (x+)+ or (x*)* nested quantifiers
  /\([^)]*\|[^)]*\)[+*]{/,     // (a|a)+ overlapping alternation with quantifier
  /(.+)\1[+*]/,                  // backreference with quantifier
];

/** Maximum allowed regex pattern length */
const MAX_PATTERN_LENGTH = 1000;

/** Default max number of custom patterns */
const DEFAULT_MAX_PATTERNS = 100;

/**
 * Validate a regex pattern is safe from ReDoS attacks.
 * Returns true if the pattern is safe, false if potentially dangerous.
 */
export function isRegexSafe(pattern: string): boolean {
  // Length check
  if (pattern.length > MAX_PATTERN_LENGTH) return false;

  // Check for dangerous nested quantifier patterns
  for (const dangerous of REDOS_DANGEROUS_PATTERNS) {
    if (dangerous.test(pattern)) return false;
  }

  // Verify it's valid regex
  try {
    new RegExp(pattern);
    return true;
  } catch {
    return false;
  }
}

// ── Built-in Secret Patterns ────────────────────────────────────────

const SECRET_PATTERNS: ResponsePattern[] = [
  // ── API Keys & Tokens ──
  {
    name: "aws-access-key",
    pattern: "(?:^|[^A-Za-z0-9])AKIA[0-9A-Z]{16}(?:[^A-Za-z0-9]|$)",
    action: "redact",
    message: "AWS Access Key ID detected in response",
    category: "secrets",
  },
  {
    name: "aws-secret-key",
    pattern: "(?:aws_secret_access_key|aws_secret_key|secret_access_key)\\s*[=:]\\s*[A-Za-z0-9/+=]{40}",
    flags: "gi",
    action: "redact",
    message: "AWS Secret Access Key detected in response",
    category: "secrets",
  },
  {
    name: "github-token",
    pattern: "(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}",
    action: "redact",
    message: "GitHub token detected in response",
    category: "secrets",
  },
  {
    name: "openai-api-key",
    pattern: "sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
    action: "redact",
    message: "OpenAI API key detected in response",
    category: "secrets",
  },
  {
    name: "generic-api-key",
    pattern: "(?:api[_-]?key|apikey|api[_-]?secret)\\s*[=:]+\\s*[\"']?[A-Za-z0-9_\\-]{20,}",
    flags: "gi",
    action: "redact",
    message: "Generic API key detected in response",
    category: "secrets",
  },
  {
    name: "bearer-token",
    pattern: "Bearer\\s+[A-Za-z0-9\\-._~+/]+=*",
    flags: "gi",
    action: "redact",
    message: "Bearer token detected in response",
    category: "secrets",
  },
  {
    name: "jwt-token",
    pattern: "eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_\\-]{10,}",
    action: "redact",
    message: "JWT token detected in response",
    category: "secrets",
  },
  // ── Private Keys & Certificates ──
  {
    name: "private-key",
    pattern: "-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    action: "block",
    message: "Private key detected in response — blocking entirely",
    category: "secrets",
  },
  {
    name: "certificate",
    pattern: "-----BEGIN CERTIFICATE-----",
    action: "redact",
    message: "Certificate detected in response",
    category: "secrets",
  },
  // ── Connection Strings ──
  {
    name: "database-url",
    pattern: "(?:postgres|mysql|mongodb|redis|amqp)://[^\\s\"']+:[^\\s\"']+@[^\\s\"']+",
    flags: "gi",
    action: "redact",
    message: "Database connection string with credentials detected",
    category: "secrets",
  },
  // ── Password Patterns ──
  {
    name: "password-assignment",
    pattern: "(?:password|passwd|pwd)\\s*[=:]\\s*[\"']?[^\\s\"']{8,}",
    flags: "gi",
    action: "redact",
    message: "Password assignment detected in response",
    category: "secrets",
  },
];

/**
 * Exfiltration marker patterns. Base64 action is configurable.
 */
function getExfiltrationPatterns(base64Action: ResponseAction): ResponsePattern[] {
  return [
    {
      name: "large-base64-blob",
      pattern: "(?:[A-Za-z0-9+/]{100,}={0,2})",
      action: base64Action,
      message: "Large base64-encoded blob detected",
      category: "exfiltration",
    },
    {
      name: "hex-dump",
      pattern: "(?:[0-9a-f]{2}[:\\s]){32,}",
      flags: "gi",
      action: "pass",
      message: "Large hex dump detected (informational)",
      category: "exfiltration",
    },
  ];
}

const PII_PATTERNS: ResponsePattern[] = [
  {
    name: "email-address",
    pattern: "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}",
    action: "redact",
    message: "Email address detected in response",
    category: "pii",
  },
  {
    name: "phone-number",
    pattern: "(?:\\+?1[\\s.-]?)?\\(?[0-9]{3}\\)?[\\s.-]?[0-9]{3}[\\s.-]?[0-9]{4}",
    action: "redact",
    message: "Phone number detected in response",
    category: "pii",
  },
  {
    name: "ssn",
    pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b",
    action: "block",
    message: "Social Security Number detected — blocking response",
    category: "pii",
  },
  {
    name: "credit-card",
    pattern: "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b",
    action: "block",
    message: "Credit card number detected — blocking response",
    category: "pii",
  },
  {
    name: "ip-address",
    pattern: "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b",
    action: "pass",
    message: "IP address detected (informational)",
    category: "pii",
  },
];

// ── Response Scanner Engine ─────────────────────────────────────────

export class ResponseScanner {
  private config: Required<Pick<ResponseScannerConfig, "enabled" | "maxResponseSize" | "oversizeAction" | "detectSecrets" | "detectPII" | "base64Action" | "maxPatterns">> & { patterns: ResponsePattern[] };
  private compiledPatterns: Array<{
    pattern: ResponsePattern;
    regex: RegExp;
  }> = [];
  private rejectedPatterns: string[] = [];

  constructor(config: ResponseScannerConfig = {}) {
    this.config = {
      enabled: config.enabled ?? true,
      maxResponseSize: config.maxResponseSize ?? 0,
      oversizeAction: config.oversizeAction ?? "redact",
      detectSecrets: config.detectSecrets ?? true,
      detectPII: config.detectPII ?? false,
      base64Action: config.base64Action ?? "pass",
      maxPatterns: config.maxPatterns ?? DEFAULT_MAX_PATTERNS,
      patterns: config.patterns ?? [],
    };

    this.compilePatterns();
  }

  /**
   * Compile all regex patterns upfront for performance.
   * Validates each pattern for ReDoS safety before compilation.
   */
  private compilePatterns(): void {
    this.compiledPatterns = [];
    this.rejectedPatterns = [];

    // Built-in secret patterns (pre-validated, always safe)
    if (this.config.detectSecrets) {
      for (const p of SECRET_PATTERNS) {
        this.safeCompile(p, true);
      }
    }

    // Exfiltration patterns with configurable base64 action
    if (this.config.detectSecrets) {
      for (const p of getExfiltrationPatterns(this.config.base64Action)) {
        this.safeCompile(p, true);
      }
    }

    // Built-in PII patterns (pre-validated, always safe)
    if (this.config.detectPII) {
      for (const p of PII_PATTERNS) {
        this.safeCompile(p, true);
      }
    }

    // User-defined patterns — enforce max count and ReDoS validation
    const userPatterns = this.config.patterns ?? [];
    const maxAllowed = this.config.maxPatterns;
    const limited = userPatterns.slice(0, maxAllowed);

    if (userPatterns.length > maxAllowed) {
      this.rejectedPatterns.push(
        `${userPatterns.length - maxAllowed} patterns exceeded max limit of ${maxAllowed}`
      );
    }

    for (const p of limited) {
      this.safeCompile(p, false);
    }
  }

  /**
   * Safely compile a pattern. For user patterns, validate ReDoS safety first.
   */
  private safeCompile(pattern: ResponsePattern, trusted: boolean): void {
    // ReDoS validation for untrusted (user) patterns
    if (!trusted) {
      if (!isRegexSafe(pattern.pattern)) {
        this.rejectedPatterns.push(
          `Pattern "${pattern.name}" rejected: potentially unsafe regex (ReDoS risk)`
        );
        return;
      }
    }

    try {
      const regex = new RegExp(pattern.pattern, pattern.flags ?? "gi");
      this.compiledPatterns.push({ pattern, regex });
    } catch {
      this.rejectedPatterns.push(
        `Pattern "${pattern.name}" rejected: invalid regex`
      );
    }
  }

  /**
   * Scan a response text for sensitive content.
   */
  scan(text: string): ScanResult {
    if (!this.config.enabled) {
      return {
        clean: true,
        action: "pass",
        findings: [],
        originalSize: Buffer.byteLength(text, "utf-8"),
      };
    }

    const originalSize = Buffer.byteLength(text, "utf-8");
    const findings: ScanFinding[] = [];

    // 1. Check response size
    if (this.config.maxResponseSize && this.config.maxResponseSize > 0) {
      if (originalSize > this.config.maxResponseSize) {
        findings.push({
          pattern: "__oversize__",
          category: "size",
          action: this.config.oversizeAction ?? "redact",
          message: `Response size (${originalSize} bytes) exceeds limit (${this.config.maxResponseSize} bytes)`,
          matchCount: 1,
        });
      }
    }

    // 2. Run all compiled patterns against the text
    for (const { pattern, regex } of this.compiledPatterns) {
      // Reset lastIndex for stateful regexes
      regex.lastIndex = 0;
      const matches = text.match(regex);

      if (matches && matches.length > 0) {
        findings.push({
          pattern: pattern.name,
          category: pattern.category ?? "custom",
          action: pattern.action,
          message: pattern.message ?? `Pattern "${pattern.name}" matched`,
          matchCount: matches.length,
          preview: this.createPreview(matches[0]),
        });
      }
    }

    if (findings.length === 0) {
      return { clean: true, action: "pass", findings: [], originalSize };
    }

    // 3. Determine overall action (highest severity wins)
    const overallAction = this.resolveAction(findings);

    // 4. Build result
    const result: ScanResult = {
      clean: false,
      action: overallAction,
      findings,
      originalSize,
    };

    // 5. Produce redacted text if action is "redact"
    if (overallAction === "redact") {
      result.redactedText = this.redactText(text, findings);
    }

    return result;
  }

  /**
   * Scan the content array from an MCP tools/call response.
   * MCP responses have the shape: { content: [{ type: "text", text: "..." }, ...] }
   */
  scanMcpResponse(result: unknown): ScanResult {
    const text = this.extractText(result);
    return this.scan(text);
  }

  /**
   * Extract all text content from an MCP response result.
   */
  private extractText(result: unknown): string {
    if (typeof result === "string") return result;
    if (!result || typeof result !== "object") return "";

    const obj = result as Record<string, unknown>;

    // MCP standard: { content: [{ type: "text", text: "..." }] }
    if (Array.isArray(obj.content)) {
      return obj.content
        .filter((c: any) => c?.type === "text" && typeof c?.text === "string")
        .map((c: any) => c.text)
        .join("\n");
    }

    // Fallback: stringify the result
    try {
      return JSON.stringify(result);
    } catch {
      return "";
    }
  }

  /**
   * Resolve the highest-severity action from all findings.
   * Priority: block > redact > pass
   */
  private resolveAction(findings: ScanFinding[]): ResponseAction {
    let highest: ResponseAction = "pass";
    for (const f of findings) {
      if (f.action === "block") return "block";
      if (f.action === "redact") highest = "redact";
    }
    return highest;
  }

  /**
   * Redact matched patterns from the text.
   * Uses generic [REDACTED] marker — never leaks pattern names.
   */
  private redactText(text: string, findings: ScanFinding[]): string {
    let redacted = text;

    // Handle oversize: truncate
    if (this.config.maxResponseSize && this.config.maxResponseSize > 0) {
      const sizeExceeded = findings.some((f) => f.pattern === "__oversize__");
      if (sizeExceeded) {
        const limit = this.config.maxResponseSize;
        redacted = redacted.slice(0, limit) + "\n\n[Agent Wall: Response truncated — exceeded size limit]";
      }
    }

    // Redact each finding's pattern matches
    for (const { pattern, regex } of this.compiledPatterns) {
      const finding = findings.find((f) => f.pattern === pattern.name);
      if (!finding || finding.action !== "redact") continue;

      regex.lastIndex = 0;
      redacted = redacted.replace(regex, `[REDACTED]`);
    }

    return redacted;
  }

  /**
   * Create a safe preview of matched content (first 4 chars + last 4).
   */
  private createPreview(match: string): string {
    if (match.length <= 8) return "***";
    const start = match.slice(0, 4);
    const end = match.slice(-4);
    return `${start}...${end}`;
  }

  /**
   * Get the current configuration.
   */
  getConfig(): ResponseScannerConfig {
    return { ...this.config };
  }

  /**
   * Get the number of compiled patterns.
   */
  getPatternCount(): number {
    return this.compiledPatterns.length;
  }

  /**
   * Get list of patterns that were rejected during compilation.
   */
  getRejectedPatterns(): string[] {
    return [...this.rejectedPatterns];
  }

  /**
   * Update configuration (e.g., after policy file reload).
   */
  updateConfig(config: ResponseScannerConfig): void {
    this.config = {
      enabled: config.enabled ?? true,
      maxResponseSize: config.maxResponseSize ?? 0,
      oversizeAction: config.oversizeAction ?? "redact",
      detectSecrets: config.detectSecrets ?? true,
      detectPII: config.detectPII ?? false,
      base64Action: config.base64Action ?? "pass",
      maxPatterns: config.maxPatterns ?? DEFAULT_MAX_PATTERNS,
      patterns: config.patterns ?? [],
    };
    this.compilePatterns();
  }
}

// ── Convenience: Default scanner ────────────────────────────────────

/**
 * Create a scanner with sensible defaults (secrets ON, PII OFF).
 */
export function createDefaultScanner(): ResponseScanner {
  return new ResponseScanner({
    enabled: true,
    maxResponseSize: 5 * 1024 * 1024, // 5MB
    oversizeAction: "redact",
    detectSecrets: true,
    detectPII: false,
  });
}
