import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as crypto from "node:crypto";
import { KillSwitch } from "./kill-switch.js";

describe("KillSwitch", () => {
  const tmpDir = path.join(os.tmpdir(), `aw-kill-test-${crypto.randomUUID()}`);
  const killFile = path.join(tmpDir, ".agent-wall-kill");

  // Setup/cleanup
  function ensureDir() {
    if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
  }

  function cleanup() {
    try { fs.unlinkSync(killFile); } catch { /* ignore */ }
    try { fs.rmdirSync(tmpDir); } catch { /* ignore */ }
  }

  afterEach(cleanup);

  describe("manual activation", () => {
    it("should be inactive by default", () => {
      const ks = new KillSwitch({ checkFile: false, registerSignal: false });
      expect(ks.isActive()).toBe(false);
      ks.dispose();
    });

    it("should activate programmatically", () => {
      const ks = new KillSwitch({ checkFile: false, registerSignal: false });
      ks.activate("Test activation");
      expect(ks.isActive()).toBe(true);
      expect(ks.getStatus().reason).toContain("Test activation");
      expect(ks.getStatus().activatedAt).not.toBeNull();
      ks.dispose();
    });

    it("should deactivate programmatically", () => {
      const ks = new KillSwitch({ checkFile: false, registerSignal: false });
      ks.activate();
      expect(ks.isActive()).toBe(true);
      ks.deactivate();
      expect(ks.isActive()).toBe(false);
      expect(ks.getStatus().reason).toBe("inactive");
      ks.dispose();
    });
  });

  describe("file-based activation", () => {
    it("should activate when kill file exists", async () => {
      ensureDir();
      const ks = new KillSwitch({
        checkFile: true,
        checkDirs: [tmpDir],
        pollIntervalMs: 50,
        registerSignal: false,
      });

      // Not active yet
      expect(ks.isActive()).toBe(false);

      // Create kill file
      fs.writeFileSync(killFile, "kill");

      // Wait for poll
      await new Promise((r) => setTimeout(r, 150));
      expect(ks.isActive()).toBe(true);
      expect(ks.getStatus().reason).toContain("Kill file detected");

      ks.dispose();
    });

    it("should deactivate when kill file is removed", async () => {
      ensureDir();
      fs.writeFileSync(killFile, "kill");

      const ks = new KillSwitch({
        checkFile: true,
        checkDirs: [tmpDir],
        pollIntervalMs: 50,
        registerSignal: false,
      });

      await new Promise((r) => setTimeout(r, 150));
      expect(ks.isActive()).toBe(true);

      // Remove kill file
      fs.unlinkSync(killFile);
      await new Promise((r) => setTimeout(r, 150));
      expect(ks.isActive()).toBe(false);

      ks.dispose();
    });
  });

  describe("disabled", () => {
    it("should never be active when disabled", () => {
      const ks = new KillSwitch({ enabled: false });
      ks.activate();
      expect(ks.isActive()).toBe(false);
      ks.dispose();
    });
  });

  describe("dispose", () => {
    it("should clean up timers", () => {
      const ks = new KillSwitch({
        checkFile: true,
        pollIntervalMs: 50,
        registerSignal: false,
      });
      // Should not throw
      ks.dispose();
      ks.dispose(); // Double dispose safe
    });
  });
});
