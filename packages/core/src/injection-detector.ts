/**
 * Agent Wall Prompt Injection Detector
 *
 * Detects prompt injection attacks in tool call arguments.
 * This is the #1 attack vector for AI agents — an attacker embeds
 * instructions in data (emails, documents, web pages) that trick
 * the AI into executing malicious actions.
 *
 * Detection layers:
 *   1. Known injection phrases (e.g., "ignore previous instructions")
 *   2. Role/system prompt markers (e.g., "<|im_start|>system")
 *   3. Instruction override patterns (e.g., "IMPORTANT: new instructions")
 *   4. Encoded injection (base64-encoded injection strings)
 *   5. Unicode obfuscation (homoglyphs, zero-width chars)
 */

import type { ToolCallParams } from "./types.js";

// ── Types ───────────────────────────────────────────────────────────

export interface InjectionDetectorConfig {
  /** Enable injection detection (default: true) */
  enabled?: boolean;
  /** Sensitivity: "low" (fewer false positives), "medium", "high" (catches more) */
  sensitivity?: "low" | "medium" | "high";
  /** Custom patterns to add (regex strings) */
  customPatterns?: string[];
  /** Tool names to exclude from injection scanning */
  excludeTools?: string[];
}

export interface InjectionScanResult {
  /** Whether injection was detected */
  detected: boolean;
  /** Confidence: "low", "medium", "high" */
  confidence: "low" | "medium" | "high";
  /** All matches found */
  matches: InjectionMatch[];
  /** Human-readable summary */
  summary: string;
}

export interface InjectionMatch {
  /** Which pattern category matched */
  category: string;
  /** The matched text (truncated for safety) */
  matched: string;
  /** Which argument key contained the match */
  argumentKey: string;
  /** Confidence level for this specific match */
  confidence: "low" | "medium" | "high";
}

// ── Injection Patterns ──────────────────────────────────────────────

interface InjectionPattern {
  category: string;
  pattern: RegExp;
  confidence: "low" | "medium" | "high";
  sensitivity: "low" | "medium" | "high";
}

/**
 * Core injection patterns organized by attack type.
 * Each pattern has a minimum sensitivity level at which it activates.
 */
const INJECTION_PATTERNS: InjectionPattern[] = [
  // ── Direct instruction override (HIGH confidence) ──
  {
    category: "instruction-override",
    pattern: /ignore\s+(all\s+)?previous\s+(instructions?|context|rules?|prompts?)/i,
    confidence: "high",
    sensitivity: "low",
  },
  {
    category: "instruction-override",
    pattern: /disregard\s+(all\s+)?(previous|above|prior|earlier)\s+(instructions?|context|rules?)/i,
    confidence: "high",
    sensitivity: "low",
  },
  {
    category: "instruction-override",
    pattern: /forget\s+(all\s+)?(your|previous|prior)\s+(instructions?|rules?|context|training)/i,
    confidence: "high",
    sensitivity: "low",
  },
  {
    category: "instruction-override",
    pattern: /override\s+(all\s+)?(previous|system|safety)\s+(instructions?|rules?|restrictions?|filters?)/i,
    confidence: "high",
    sensitivity: "low",
  },
  {
    category: "instruction-override",
    pattern: /new\s+instructions?:\s/i,
    confidence: "high",
    sensitivity: "low",
  },
  {
    category: "instruction-override",
    pattern: /you\s+are\s+now\s+(a|an|in)\s/i,
    confidence: "high",
    sensitivity: "low",
  },
  {
    category: "instruction-override",
    pattern: /from\s+now\s+on,?\s+(you|ignore|disregard|forget)/i,
    confidence: "high",
    sensitivity: "low",
  },

  // ── System/Role prompt markers (HIGH confidence) ──
  {
    category: "prompt-marker",
    pattern: /<\|im_start\|>system/i,
    confidence: "high",
    sensitivity: "low",
  },
  {
    category: "prompt-marker",
    pattern: /<\|system\|>/i,
    confidence: "high",
    sensitivity: "low",
  },
  {
    category: "prompt-marker",
    pattern: /\[SYSTEM\]\s*:/i,
    confidence: "high",
    sensitivity: "low",
  },
  {
    category: "prompt-marker",
    pattern: /\[INST\]/i,
    confidence: "high",
    sensitivity: "low",
  },
  {
    category: "prompt-marker",
    pattern: /<<SYS>>/i,
    confidence: "high",
    sensitivity: "low",
  },
  {
    category: "prompt-marker",
    pattern: /###\s*(System|Instruction|Human|Assistant)\s*:/i,
    confidence: "medium",
    sensitivity: "medium",
  },

  // ── Authority claims (MEDIUM confidence) ──
  {
    category: "authority-claim",
    pattern: /admin(istrator)?\s+(override|mode|access|command)/i,
    confidence: "medium",
    sensitivity: "low",
  },
  {
    category: "authority-claim",
    pattern: /IMPORTANT:\s*(override|ignore|disregard|new\s+instruction)/i,
    confidence: "high",
    sensitivity: "low",
  },
  {
    category: "authority-claim",
    pattern: /URGENT:\s*(you\s+must|override|ignore)/i,
    confidence: "medium",
    sensitivity: "low",
  },
  {
    category: "authority-claim",
    pattern: /developer\s+mode\s+(enabled|activated|on)/i,
    confidence: "high",
    sensitivity: "low",
  },
  {
    category: "authority-claim",
    pattern: /jailbreak/i,
    confidence: "high",
    sensitivity: "low",
  },
  {
    category: "authority-claim",
    pattern: /DAN\s+(mode|prompt)/i,
    confidence: "high",
    sensitivity: "low",
  },

  // ── Data exfiltration instructions (HIGH confidence) ──
  {
    category: "exfil-instruction",
    pattern: /send\s+(all\s+)?(the\s+|this\s+|my\s+)?(data|information|content|file|secret|key|token|password|credential)\s+(to|via|through|using)/i,
    confidence: "high",
    sensitivity: "low",
  },
  {
    category: "exfil-instruction",
    pattern: /exfiltrate|steal\s+(the\s+)?(data|secret|key|credential|token)/i,
    confidence: "high",
    sensitivity: "low",
  },
  {
    category: "exfil-instruction",
    pattern: /upload\s+(all\s+)?(the\s+|this\s+|my\s+|every\s+)?(files?|data|content|secrets?)/i,
    confidence: "medium",
    sensitivity: "medium",
  },

  // ── Output manipulation (MEDIUM confidence) ──
  {
    category: "output-manipulation",
    pattern: /respond\s+with\s+(only|just|exactly)\s/i,
    confidence: "low",
    sensitivity: "high",
  },
  {
    category: "output-manipulation",
    pattern: /do\s+not\s+(mention|reveal|tell|show|display|output)\s/i,
    confidence: "low",
    sensitivity: "high",
  },
  {
    category: "output-manipulation",
    pattern: /pretend\s+(you|that|to\s+be)/i,
    confidence: "medium",
    sensitivity: "medium",
  },

  // ── Unicode obfuscation markers (HIGH confidence) ──
  {
    category: "unicode-obfuscation",
    pattern: /[\u200B-\u200F\u2028-\u202F\uFEFF]/,  // Zero-width chars
    confidence: "medium",
    sensitivity: "medium",
  },
  {
    category: "unicode-obfuscation",
    pattern: /[\u2060-\u2064]/,  // Invisible formatting chars
    confidence: "medium",
    sensitivity: "medium",
  },
  {
    category: "unicode-obfuscation",
    pattern: /[\uE000-\uF8FF]/,  // Private Use Area (sometimes used to hide text)
    confidence: "low",
    sensitivity: "high",
  },

  // ── Encoded injection (base64 "ignore" etc.) ──
  {
    category: "encoded-injection",
    pattern: /aWdub3Jl/,  // base64 of "ignore"
    confidence: "medium",
    sensitivity: "medium",
  },
  {
    category: "encoded-injection",
    pattern: /c3lzdGVt/,  // base64 of "system"
    confidence: "low",
    sensitivity: "high",
  },

  // ── Delimiter injection (trying to break out of a tool argument) ──
  {
    category: "delimiter-injection",
    pattern: /\}\s*\]\s*\}\s*\{/,  // Trying to close JSON and start new object
    confidence: "medium",
    sensitivity: "medium",
  },
  {
    category: "delimiter-injection",
    pattern: /```\s*(system|instruction|prompt)/i,  // Code block with system marker
    confidence: "medium",
    sensitivity: "medium",
  },
];

// ── Sensitivity levels (numeric for comparison) ──

const SENSITIVITY_LEVELS: Record<string, number> = {
  low: 1,
  medium: 2,
  high: 3,
};

// ── Injection Detector ──────────────────────────────────────────────

export class InjectionDetector {
  private config: Required<InjectionDetectorConfig>;
  private customRegexes: RegExp[] = [];

  constructor(config: InjectionDetectorConfig = {}) {
    this.config = {
      enabled: config.enabled ?? true,
      sensitivity: config.sensitivity ?? "medium",
      customPatterns: config.customPatterns ?? [],
      excludeTools: config.excludeTools ?? [],
    };

    // Compile custom patterns
    for (const p of this.config.customPatterns) {
      try {
        this.customRegexes.push(new RegExp(p, "i"));
      } catch {
        // Log and skip invalid regex so users know which pattern failed
        process.stderr.write(`[agent-wall] Warning: invalid custom injection pattern: "${p}"\n`);
      }
    }
  }

  /**
   * Scan a tool call's arguments for prompt injection.
   */
  scan(toolCall: ToolCallParams): InjectionScanResult {
    if (!this.config.enabled) {
      return { detected: false, confidence: "low", matches: [], summary: "Injection detection disabled" };
    }

    // Skip excluded tools
    if (this.config.excludeTools.includes(toolCall.name)) {
      return { detected: false, confidence: "low", matches: [], summary: "Tool excluded from injection scanning" };
    }

    const matches: InjectionMatch[] = [];
    const args = toolCall.arguments ?? {};
    const sensitivityLevel = SENSITIVITY_LEVELS[this.config.sensitivity] ?? 2;

    // Scan each argument value
    for (const [key, value] of Object.entries(args)) {
      const strValue = this.extractString(value);
      if (!strValue || strValue.length < 5) continue;

      // Run built-in patterns
      for (const injPattern of INJECTION_PATTERNS) {
        const patternSensitivity = SENSITIVITY_LEVELS[injPattern.sensitivity] ?? 2;
        if (patternSensitivity > sensitivityLevel) continue;

        if (injPattern.pattern.test(strValue)) {
          const match = strValue.match(injPattern.pattern);
          matches.push({
            category: injPattern.category,
            matched: match ? match[0].slice(0, 80) : "***",
            argumentKey: key,
            confidence: injPattern.confidence,
          });
        }
      }

      // Run custom patterns
      for (const regex of this.customRegexes) {
        regex.lastIndex = 0;
        if (regex.test(strValue)) {
          matches.push({
            category: "custom",
            matched: "custom pattern match",
            argumentKey: key,
            confidence: "medium",
          });
        }
      }
    }

    if (matches.length === 0) {
      return { detected: false, confidence: "low", matches: [], summary: "No injection detected" };
    }

    // Overall confidence = highest match confidence
    const highestConfidence = matches.reduce((best, m) => {
      const mLevel = SENSITIVITY_LEVELS[m.confidence] ?? 0;
      const bLevel = SENSITIVITY_LEVELS[best] ?? 0;
      return mLevel > bLevel ? m.confidence : best;
    }, "low" as "low" | "medium" | "high");

    const categories = [...new Set(matches.map((m) => m.category))];
    const summary = `Prompt injection detected (${highestConfidence} confidence): ${categories.join(", ")}. ${matches.length} pattern(s) matched.`;

    return {
      detected: true,
      confidence: highestConfidence,
      matches,
      summary,
    };
  }

  /**
   * Extract a string from an argument value (handles nested objects).
   */
  private extractString(value: unknown): string {
    if (typeof value === "string") return value;
    if (typeof value === "number" || typeof value === "boolean") return String(value);
    if (value === null || value === undefined) return "";
    try {
      return JSON.stringify(value);
    } catch {
      return "";
    }
  }
}
