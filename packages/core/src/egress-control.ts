/**
 * Agent Wall Egress Control (URL/SSRF Protection)
 *
 * Inspects tool call arguments for URLs and blocks requests to:
 *   - Private/internal IPs (RFC1918: 10.x, 172.16-31.x, 192.168.x)
 *   - Loopback addresses (127.x, ::1, localhost)
 *   - Link-local addresses (169.254.x — AWS/cloud metadata endpoint)
 *   - Cloud metadata endpoints (169.254.169.254)
 *   - Blocked domains (configurable)
 *
 * Supports allowlist mode: only explicitly allowed domains pass.
 */

import type { ToolCallParams } from "./types.js";

// ── Types ───────────────────────────────────────────────────────────

export interface EgressControlConfig {
  /** Enable egress control (default: true when configured) */
  enabled?: boolean;
  /** Allowed domains (if set, ONLY these domains pass — allowlist mode) */
  allowedDomains?: string[];
  /** Blocked domains (blocklist mode, used when allowedDomains is not set) */
  blockedDomains?: string[];
  /** Block private/internal IPs (default: true) */
  blockPrivateIPs?: boolean;
  /** Block cloud metadata endpoints (default: true) */
  blockMetadataEndpoints?: boolean;
  /** Tool names to exclude from egress scanning */
  excludeTools?: string[];
}

export interface EgressCheckResult {
  /** Whether the call is safe to proceed */
  allowed: boolean;
  /** URLs found in arguments */
  urlsFound: EgressUrlInfo[];
  /** URLs that were blocked */
  blocked: EgressUrlInfo[];
  /** Human-readable summary */
  summary: string;
}

export interface EgressUrlInfo {
  /** The original URL string */
  url: string;
  /** Parsed hostname */
  hostname: string;
  /** Why it was blocked (if blocked) */
  reason?: string;
  /** Which argument key contained this URL */
  argumentKey: string;
}

// ── Private IP Ranges ───────────────────────────────────────────────

/**
 * Check if an IP address is in a private/internal range.
 */
function isPrivateIP(ip: string): boolean {
  // IPv4 private ranges
  const parts = ip.split(".").map(Number);
  if (parts.length === 4 && parts.every((p) => p >= 0 && p <= 255)) {
    // 10.0.0.0/8
    if (parts[0] === 10) return true;
    // 172.16.0.0/12
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    // 192.168.0.0/16
    if (parts[0] === 192 && parts[1] === 168) return true;
    // 127.0.0.0/8 (loopback)
    if (parts[0] === 127) return true;
    // 169.254.0.0/16 (link-local, includes cloud metadata)
    if (parts[0] === 169 && parts[1] === 254) return true;
    // 0.0.0.0
    if (parts.every((p) => p === 0)) return true;
  }

  // IPv6 loopback
  if (ip === "::1" || ip === "[::1]") return true;
  // IPv6 link-local
  if (ip.toLowerCase().startsWith("fe80:")) return true;
  // IPv6 private (fc00::/7)
  if (ip.toLowerCase().startsWith("fc") || ip.toLowerCase().startsWith("fd")) return true;

  return false;
}

/**
 * Known cloud metadata endpoints.
 */
const METADATA_ENDPOINTS = [
  "169.254.169.254",     // AWS, GCP, Azure
  "metadata.google.internal",
  "metadata.goog",
  "100.100.100.200",     // Alibaba Cloud
  "169.254.170.2",       // AWS ECS task metadata
];

// ── URL Extraction ──────────────────────────────────────────────────

/**
 * Extract URLs from a string value.
 * Finds http://, https://, and bare domain patterns.
 */
const URL_REGEX = /https?:\/\/[^\s"'<>\])}]+/gi;

function extractUrls(value: string): string[] {
  const matches = value.match(URL_REGEX);
  return matches ? [...new Set(matches)] : [];
}

/**
 * Parse hostname from a URL string, handling edge cases.
 * Note: URL parser normalizes hex IPs (0x7f000001 → 127.0.0.1).
 */
function parseHostname(urlStr: string): string | null {
  try {
    const url = new URL(urlStr);
    return url.hostname;
  } catch {
    // Try to extract hostname manually for malformed URLs
    const match = urlStr.match(/https?:\/\/([^/:?\s#]+)/i);
    return match ? match[1] : null;
  }
}

/**
 * Extract raw hostname from URL before URL parser normalizes it.
 * This preserves hex/decimal IP encodings for obfuscation detection.
 */
function extractRawHostname(urlStr: string): string | null {
  const match = urlStr.match(/https?:\/\/([^/:?\s#]+)/i);
  return match ? match[1] : null;
}

// ── Egress Control ──────────────────────────────────────────────────

export class EgressControl {
  private config: Required<EgressControlConfig>;

  constructor(config: EgressControlConfig = {}) {
    this.config = {
      enabled: config.enabled ?? true,
      allowedDomains: config.allowedDomains ?? [],
      blockedDomains: config.blockedDomains ?? [],
      blockPrivateIPs: config.blockPrivateIPs ?? true,
      blockMetadataEndpoints: config.blockMetadataEndpoints ?? true,
      excludeTools: config.excludeTools ?? [],
    };
  }

  /**
   * Check a tool call's arguments for blocked URLs.
   */
  check(toolCall: ToolCallParams): EgressCheckResult {
    if (!this.config.enabled) {
      return { allowed: true, urlsFound: [], blocked: [], summary: "Egress control disabled" };
    }

    if (this.config.excludeTools.includes(toolCall.name)) {
      return { allowed: true, urlsFound: [], blocked: [], summary: "Tool excluded from egress control" };
    }

    const urlsFound: EgressUrlInfo[] = [];
    const blocked: EgressUrlInfo[] = [];
    const args = toolCall.arguments ?? {};

    // Extract URLs from all string arguments
    for (const [key, value] of Object.entries(args)) {
      const strValue = typeof value === "string" ? value : JSON.stringify(value ?? "");
      const urls = extractUrls(strValue);

      for (const url of urls) {
        // Extract raw hostname (before URL parser normalizes it)
        const rawHostname = extractRawHostname(url);
        const hostname = parseHostname(url);
        if (!hostname) continue;

        const info: EgressUrlInfo = { url, hostname, argumentKey: key };
        urlsFound.push(info);

        // Check if blocked (pass raw hostname for obfuscation detection)
        const blockReason = this.checkUrl(hostname, url, rawHostname);
        if (blockReason) {
          blocked.push({ ...info, reason: blockReason });
        }
      }
    }

    if (blocked.length === 0) {
      return {
        allowed: true,
        urlsFound,
        blocked: [],
        summary: urlsFound.length > 0
          ? `${urlsFound.length} URL(s) found, all allowed`
          : "No URLs found in arguments",
      };
    }

    const reasons = [...new Set(blocked.map((b) => b.reason))];
    return {
      allowed: false,
      urlsFound,
      blocked,
      summary: `Blocked ${blocked.length} URL(s): ${reasons.join("; ")}`,
    };
  }

  /**
   * Check a single hostname/URL against all rules.
   * Returns the block reason, or null if allowed.
   *
   * Check order matters: more specific checks (obfuscated, metadata) run
   * before generic private IP, so the reason message is precise.
   */
  private checkUrl(hostname: string, fullUrl: string, rawHostname?: string | null): string | null {
    const lowerHost = hostname.toLowerCase();
    const rawHost = rawHostname ?? hostname;

    // 1. Allowlist mode — if configured, ONLY listed domains pass
    if (this.config.allowedDomains.length > 0) {
      const allowed = this.config.allowedDomains.some((d) =>
        lowerHost === d.toLowerCase() || lowerHost.endsWith("." + d.toLowerCase())
      );
      if (!allowed) {
        return `Domain "${hostname}" is not in the allowed domains list`;
      }
      // If allowed, still check private IPs (defense in depth)
    }

    // 2. Blocklist mode
    if (this.config.blockedDomains.length > 0) {
      const isBlocked = this.config.blockedDomains.some((d) =>
        lowerHost === d.toLowerCase() || lowerHost.endsWith("." + d.toLowerCase())
      );
      if (isBlocked) {
        return `Domain "${hostname}" is in the blocked domains list`;
      }
    }

    // 3. Obfuscated IP check (BEFORE private IP — uses raw hostname before URL normalization)
    if (this.config.blockPrivateIPs) {
      if (/^0x[0-9a-f]+$/i.test(rawHost) || /^\d{8,}$/.test(rawHost)) {
        return `Obfuscated IP address "${rawHost}" is blocked (potential SSRF bypass)`;
      }
    }

    // 4. Cloud metadata endpoint check (BEFORE generic private IP for precise messaging)
    if (this.config.blockMetadataEndpoints) {
      if (METADATA_ENDPOINTS.some((ep) => lowerHost === ep.toLowerCase())) {
        return `Cloud metadata endpoint "${hostname}" is blocked`;
      }

      if (fullUrl.includes("/latest/meta-data") || fullUrl.includes("/metadata/instance")) {
        return `Cloud metadata access is blocked`;
      }
    }

    // 5. Private IP check
    if (this.config.blockPrivateIPs) {
      if (isPrivateIP(hostname)) {
        return `Private/internal IP address "${hostname}" is blocked (SSRF protection)`;
      }

      // Also check for localhost aliases
      if (lowerHost === "localhost" || lowerHost === "ip6-localhost") {
        return `Localhost address is blocked (SSRF protection)`;
      }
    }

    return null;
  }
}
