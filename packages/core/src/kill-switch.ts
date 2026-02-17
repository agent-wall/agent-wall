/**
 * Agent Wall Kill Switch
 *
 * Emergency "deny all" mechanism for instantly shutting down
 * all tool call forwarding. Three activation methods:
 *
 *   1. File-based: touch .agent-wall-kill in cwd or home dir
 *   2. Programmatic: killSwitch.activate() / killSwitch.deactivate()
 *   3. Signal-based: SIGUSR2 toggles the kill switch (Unix only)
 *
 * When active, ALL tool calls are denied immediately with a clear message.
 * The kill switch is checked FIRST in the proxy pipeline — before policy
 * engine, injection detection, or any other check.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

// ── Types ───────────────────────────────────────────────────────────

export interface KillSwitchConfig {
  /** Enable kill switch checking (default: true) */
  enabled?: boolean;
  /** Check for kill file on filesystem (default: true) */
  checkFile?: boolean;
  /** File names to check (default: [".agent-wall-kill"]) */
  killFileNames?: string[];
  /** Directories to check for kill files (default: [cwd, home]) */
  checkDirs?: string[];
  /** How often to check the kill file in ms (default: 1000) */
  pollIntervalMs?: number;
  /** Register SIGUSR2 signal handler to toggle (default: true on Unix) */
  registerSignal?: boolean;
}

export interface KillSwitchStatus {
  /** Whether the kill switch is currently active */
  active: boolean;
  /** How it was activated */
  reason: string;
  /** When it was activated */
  activatedAt: string | null;
}

// ── Constants ───────────────────────────────────────────────────────

const DEFAULT_KILL_FILES = [".agent-wall-kill"];
const DEFAULT_POLL_INTERVAL = 1000;

// ── Kill Switch ─────────────────────────────────────────────────────

export class KillSwitch {
  private config: Required<KillSwitchConfig>;
  private manuallyActive = false;
  private fileActive = false;
  private activeReason = "";
  private activatedAt: string | null = null;
  private pollTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: KillSwitchConfig = {}) {
    const isUnix = process.platform !== "win32";

    this.config = {
      enabled: config.enabled ?? true,
      checkFile: config.checkFile ?? true,
      killFileNames: config.killFileNames ?? DEFAULT_KILL_FILES,
      checkDirs: config.checkDirs ?? [process.cwd(), os.homedir()],
      pollIntervalMs: config.pollIntervalMs ?? DEFAULT_POLL_INTERVAL,
      registerSignal: config.registerSignal ?? isUnix,
    };

    if (this.config.enabled) {
      this.startPolling();
      this.registerSignalHandler();
    }
  }

  /**
   * Check if the kill switch is currently active.
   * This should be called at the TOP of the proxy pipeline.
   */
  isActive(): boolean {
    if (!this.config.enabled) return false;
    return this.manuallyActive || this.fileActive;
  }

  /**
   * Get the current kill switch status.
   */
  getStatus(): KillSwitchStatus {
    return {
      active: this.isActive(),
      reason: this.isActive() ? this.activeReason : "inactive",
      activatedAt: this.isActive() ? this.activatedAt : null,
    };
  }

  /**
   * Programmatically activate the kill switch.
   */
  activate(reason: string = "Manually activated"): void {
    this.manuallyActive = true;
    this.activeReason = reason;
    this.activatedAt = new Date().toISOString();
  }

  /**
   * Programmatically deactivate the kill switch.
   * Note: file-based kill switch must be deactivated by removing the file.
   */
  deactivate(): void {
    this.manuallyActive = false;
    if (!this.fileActive) {
      this.activeReason = "";
      this.activatedAt = null;
    }
  }

  /**
   * Start polling for kill files.
   */
  private startPolling(): void {
    if (!this.config.checkFile) return;

    // Check immediately
    this.checkKillFiles();

    // Then poll periodically
    this.pollTimer = setInterval(() => {
      this.checkKillFiles();
    }, this.config.pollIntervalMs);
    this.pollTimer.unref();
  }

  /**
   * Check if any kill file exists.
   */
  private checkKillFiles(): void {
    for (const dir of this.config.checkDirs) {
      for (const fileName of this.config.killFileNames) {
        const filePath = path.join(dir, fileName);
        try {
          if (fs.existsSync(filePath)) {
            if (!this.fileActive) {
              this.fileActive = true;
              this.activeReason = `Kill file detected: ${filePath}`;
              this.activatedAt = new Date().toISOString();
            }
            return;
          }
        } catch {
          // Ignore filesystem errors during polling
        }
      }
    }
    // No kill file found — deactivate file-based kill switch
    if (this.fileActive) {
      this.fileActive = false;
      if (!this.manuallyActive) {
        this.activeReason = "";
        this.activatedAt = null;
      }
    }
  }

  /**
   * Register SIGUSR2 signal handler to toggle kill switch.
   * SIGUSR2 is used (not SIGUSR1) because some tools use SIGUSR1.
   */
  private registerSignalHandler(): void {
    if (!this.config.registerSignal) return;

    try {
      process.on("SIGUSR2", () => {
        if (this.manuallyActive) {
          this.deactivate();
          process.stderr.write("[agent-wall] Kill switch DEACTIVATED via SIGUSR2\n");
        } else {
          this.activate("Activated via SIGUSR2 signal");
          process.stderr.write("[agent-wall] Kill switch ACTIVATED via SIGUSR2\n");
        }
      });
    } catch {
      // SIGUSR2 not available on this platform (Windows)
    }
  }

  /**
   * Stop the kill switch (cleanup timers and signal handlers).
   */
  dispose(): void {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }
}
