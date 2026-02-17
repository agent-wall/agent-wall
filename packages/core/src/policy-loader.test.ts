/**
 * Tests for PolicyLoader — YAML config loading and validation.
 */

import { describe, it, expect } from "vitest";
import { parsePolicyYaml, getDefaultPolicy, generateDefaultConfigYaml } from "./policy-loader.js";

describe("parsePolicyYaml", () => {
  it("should parse a valid policy YAML", () => {
    const yaml = `
version: 1
defaultAction: deny
rules:
  - name: allow-read
    tool: read_file
    action: allow
  - name: block-shell
    tool: shell_exec
    action: deny
    message: "No shell access"
`;

    const config = parsePolicyYaml(yaml);
    expect(config.version).toBe(1);
    expect(config.defaultAction).toBe("deny");
    expect(config.rules).toHaveLength(2);
    expect(config.rules[0].name).toBe("allow-read");
    expect(config.rules[0].action).toBe("allow");
    expect(config.rules[1].message).toBe("No shell access");
  });

  it("should parse rules with argument matching", () => {
    const yaml = `
version: 1
rules:
  - name: block-ssh
    tool: "*"
    match:
      arguments:
        path: "*/.ssh/**"
    action: deny
`;

    const config = parsePolicyYaml(yaml);
    expect(config.rules[0].match?.arguments?.path).toBe("*/.ssh/**");
  });

  it("should parse rules with rate limiting", () => {
    const yaml = `
version: 1
globalRateLimit:
  maxCalls: 100
  windowSeconds: 60
rules:
  - name: limited
    tool: read_file
    action: allow
    rateLimit:
      maxCalls: 10
      windowSeconds: 30
`;

    const config = parsePolicyYaml(yaml);
    expect(config.globalRateLimit?.maxCalls).toBe(100);
    expect(config.rules[0].rateLimit?.maxCalls).toBe(10);
  });

  it("should parse responseScanning configuration", () => {
    const yaml = `
version: 1
responseScanning:
  enabled: true
  maxResponseSize: 5242880
  oversizeAction: redact
  detectSecrets: true
  detectPII: true
  patterns:
    - name: internal-url
      pattern: "https?://internal\\\\.[a-z]+\\\\.corp"
      action: redact
      message: "Internal URL detected"
      category: custom
rules:
  - name: allow-all
    tool: "*"
    action: allow
`;

    const config = parsePolicyYaml(yaml);
    expect(config.responseScanning).toBeDefined();
    expect(config.responseScanning!.enabled).toBe(true);
    expect(config.responseScanning!.maxResponseSize).toBe(5242880);
    expect(config.responseScanning!.oversizeAction).toBe("redact");
    expect(config.responseScanning!.detectSecrets).toBe(true);
    expect(config.responseScanning!.detectPII).toBe(true);
    expect(config.responseScanning!.patterns).toHaveLength(1);
    expect(config.responseScanning!.patterns![0].name).toBe("internal-url");
    expect(config.responseScanning!.patterns![0].action).toBe("redact");
  });

  it("should accept config without responseScanning section", () => {
    const yaml = `
version: 1
rules:
  - name: test
    tool: "*"
    action: allow
`;

    const config = parsePolicyYaml(yaml);
    expect(config.responseScanning).toBeUndefined();
  });

  it("should throw on invalid YAML structure", () => {
    expect(() => parsePolicyYaml("version: 1\nrules: not-an-array")).toThrow();
    expect(() => parsePolicyYaml("version: 1")).toThrow();
    expect(() => parsePolicyYaml("{}")).toThrow();
  });

  it("should throw on invalid action values", () => {
    const yaml = `
version: 1
rules:
  - name: bad
    tool: "*"
    action: invalid_action
`;
    expect(() => parsePolicyYaml(yaml)).toThrow();
  });

  it("should throw when rule is missing required fields", () => {
    const yaml = `
version: 1
rules:
  - tool: "*"
    action: allow
`;
    // Missing "name"
    expect(() => parsePolicyYaml(yaml)).toThrow();
  });
});

describe("getDefaultPolicy", () => {
  it("should return a valid default config", () => {
    const config = getDefaultPolicy();
    expect(config.version).toBe(1);
    expect(config.rules.length).toBeGreaterThan(0);
    expect(config.defaultAction).toBe("prompt");
  });

  it("should include response scanning defaults", () => {
    const config = getDefaultPolicy();
    expect(config.responseScanning).toBeDefined();
    expect(config.responseScanning!.enabled).toBe(true);
    expect(config.responseScanning!.detectSecrets).toBe(true);
    expect(config.responseScanning!.detectPII).toBe(false);
  });

  it("should include critical security rules", () => {
    const config = getDefaultPolicy();
    const names = config.rules.map((r) => r.name);

    expect(names).toContain("block-ssh-keys");
    expect(names).toContain("block-env-files");
    expect(names).toContain("block-credential-files");
    expect(names).toContain("block-curl-exfil");
  });

  it("should include bypass-resistant exfiltration rules", () => {
    const config = getDefaultPolicy();
    const names = config.rules.map((r) => r.name);

    expect(names).toContain("block-powershell-exfil");
    expect(names).toContain("block-dns-exfil");
    expect(names).toContain("approve-script-exec");
  });

  it("should have deny rules before allow rules", () => {
    const config = getDefaultPolicy();
    const firstDeny = config.rules.findIndex((r) => r.action === "deny");
    const firstAllow = config.rules.findIndex((r) => r.action === "allow");

    expect(firstDeny).toBeLessThan(firstAllow);
  });
});

describe("generateDefaultConfigYaml", () => {
  it("should generate parseable YAML", () => {
    const yaml = generateDefaultConfigYaml();
    const config = parsePolicyYaml(yaml);
    expect(config.version).toBe(1);
    expect(config.rules.length).toBeGreaterThan(0);
  });

  it("should include helpful comments", () => {
    const yaml = generateDefaultConfigYaml();
    expect(yaml).toContain("# Agent Wall Policy Configuration");
    expect(yaml).toContain("# Rules are evaluated in order");
    expect(yaml).toContain("responseScanning");
    expect(yaml).toContain("detectSecrets");
  });
});
