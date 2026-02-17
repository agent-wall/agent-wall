/**
 * Agent Wall Dashboard Server
 *
 * HTTP + WebSocket server that bridges proxy events to a browser-based
 * security dashboard. Serves the built React SPA and streams real-time
 * events over WebSocket.
 *
 * Usage:
 *   const dashboard = new DashboardServer({ port: 61100, proxy, killSwitch });
 *   await dashboard.start();
 */

import * as http from "node:http";
import * as fs from "node:fs";
import * as path from "node:path";
import { WebSocketServer, type WebSocket } from "ws";
import type { StdioProxy } from "./proxy.js";
import type { KillSwitch } from "./kill-switch.js";
import type { PolicyEngine } from "./policy-engine.js";
import type { AuditLogger, AuditEntry } from "./audit-logger.js";

// ── WebSocket Message Types ────────────────────────────────────────

export type WsMessageType =
  | "event"
  | "stats"
  | "audit"
  | "killSwitch"
  | "ruleHits"
  | "config"
  | "welcome";

export interface WsMessage<T = unknown> {
  type: WsMessageType;
  ts: string;
  payload: T;
}

export interface ProxyEventPayload {
  event: string;
  tool: string;
  detail: string;
  severity: "info" | "warn" | "critical";
}

export interface StatsPayload {
  forwarded: number;
  denied: number;
  prompted: number;
  total: number;
  scanned: number;
  responseBlocked: number;
  responseRedacted: number;
  uptime: number;
  killSwitchActive: boolean;
}

export interface RuleHitsPayload {
  rules: Array<{
    name: string;
    action: string;
    hits: number;
  }>;
}

export interface ConfigPayload {
  defaultAction: string;
  ruleCount: number;
  mode: string;
  security: {
    injection: boolean;
    egress: boolean;
    killSwitch: boolean;
    chain: boolean;
    signing: boolean;
  };
}

// ── Client → Server Messages ───────────────────────────────────────

export type ClientWsMessage =
  | { type: "toggleKillSwitch" }
  | { type: "getStats" }
  | { type: "getConfig" }
  | { type: "getAuditLog"; limit?: number; filter?: string };

// ── MIME Types ──────────────────────────────────────────────────────

const MIME_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
};

// ── Dashboard Server ───────────────────────────────────────────────

export interface DashboardServerOptions {
  /** Port to listen on */
  port: number;
  /** The proxy instance to observe */
  proxy: StdioProxy;
  /** Kill switch instance (for toggle control) */
  killSwitch?: KillSwitch;
  /** Policy engine (for config summary) */
  policyEngine?: PolicyEngine;
  /** Audit logger (for log queries) */
  logger?: AuditLogger;
  /** Directory containing the built React SPA */
  staticDir?: string;
  /** Stats broadcast interval in ms (default: 2000) */
  statsIntervalMs?: number;
}

export class DashboardServer {
  private httpServer: http.Server | null = null;
  private wss: WebSocketServer | null = null;
  private statsTimer: ReturnType<typeof setInterval> | null = null;
  private ruleHitCounts = new Map<string, { action: string; hits: number }>();
  private startTime = Date.now();
  private options: DashboardServerOptions;

  constructor(options: DashboardServerOptions) {
    this.options = options;
  }

  async start(): Promise<void> {
    const { port, staticDir, statsIntervalMs = 2000 } = this.options;

    // Create HTTP server for static files
    this.httpServer = http.createServer((req, res) => {
      this.handleHttpRequest(req, res, staticDir);
    });

    // Create WebSocket server on the same port
    this.wss = new WebSocketServer({ server: this.httpServer });
    this.wss.on("error", () => {
      // Handled by httpServer error in start() promise
    });

    this.wss.on("connection", (ws) => {
      // Send welcome message with current state
      this.sendTo(ws, {
        type: "welcome",
        ts: new Date().toISOString(),
        payload: { message: "Agent Wall Dashboard connected" },
      });

      // Send current stats immediately
      this.sendStats(ws);

      // Send current config
      this.sendConfig(ws);

      // Send current rule hits
      this.sendRuleHits(ws);

      // Handle incoming messages from dashboard
      ws.on("message", (data) => {
        try {
          const msg: ClientWsMessage = JSON.parse(data.toString());
          this.handleClientMessage(ws, msg);
        } catch {
          // Ignore malformed messages
        }
      });
    });

    // Wire proxy events
    this.wireProxyEvents();

    // Broadcast stats on interval
    this.statsTimer = setInterval(() => {
      this.broadcastStats();
    }, statsIntervalMs);

    // Start listening
    return new Promise<void>((resolve, reject) => {
      this.httpServer!.on("error", reject);
      this.httpServer!.listen(port, () => resolve());
    });
  }

  async stop(): Promise<void> {
    if (this.statsTimer) {
      clearInterval(this.statsTimer);
      this.statsTimer = null;
    }

    // Close all WebSocket connections
    if (this.wss) {
      for (const ws of this.wss.clients) {
        ws.close();
      }
      this.wss.close();
      this.wss = null;
    }

    // Close HTTP server
    if (this.httpServer) {
      return new Promise<void>((resolve) => {
        this.httpServer!.close(() => resolve());
        this.httpServer = null;
      });
    }
  }

  /** Get the actual port (useful when port 0 is used for testing) */
  getPort(): number {
    const addr = this.httpServer?.address();
    if (addr && typeof addr === "object") return addr.port;
    return this.options.port;
  }

  // ── Event Wiring ──────────────────────────────────────────────────

  private wireProxyEvents(): void {
    const { proxy } = this.options;

    const eventMap: Array<{
      event: string;
      severity: "info" | "warn" | "critical";
      getArgs: (tool: string, detail?: string) => { tool: string; detail: string };
    }> = [
      { event: "allowed", severity: "info", getArgs: (tool) => ({ tool, detail: "" }) },
      { event: "denied", severity: "warn", getArgs: (tool, msg = "") => ({ tool, detail: msg }) },
      { event: "prompted", severity: "info", getArgs: (tool, msg = "") => ({ tool, detail: msg }) },
      { event: "responseBlocked", severity: "warn", getArgs: (tool, findings = "") => ({ tool, detail: findings }) },
      { event: "responseRedacted", severity: "info", getArgs: (tool, findings = "") => ({ tool, detail: findings }) },
      { event: "injectionDetected", severity: "critical", getArgs: (tool, summary = "") => ({ tool, detail: summary }) },
      { event: "egressBlocked", severity: "critical", getArgs: (tool, summary = "") => ({ tool, detail: summary }) },
      { event: "killSwitchActive", severity: "critical", getArgs: (tool) => ({ tool, detail: "Kill switch is active — all calls denied" }) },
      { event: "chainDetected", severity: "warn", getArgs: (tool, summary = "") => ({ tool, detail: summary }) },
    ];

    for (const { event, severity, getArgs } of eventMap) {
      proxy.on(event, (tool: string, detail?: string) => {
        const parsed = getArgs(tool, detail);
        this.broadcast({
          type: "event",
          ts: new Date().toISOString(),
          payload: { event, tool: parsed.tool, detail: parsed.detail, severity } as ProxyEventPayload,
        });
      });
    }
  }

  /** Called by the audit logger's onEntry callback */
  handleAuditEntry(entry: AuditEntry): void {
    // Track rule hits
    if (entry.verdict?.rule) {
      const key = entry.verdict.rule;
      const existing = this.ruleHitCounts.get(key);
      if (existing) {
        existing.hits++;
      } else {
        this.ruleHitCounts.set(key, {
          action: entry.verdict.action,
          hits: 1,
        });
      }
    }

    // Broadcast audit entry to all clients
    this.broadcast({
      type: "audit",
      ts: new Date().toISOString(),
      payload: entry,
    });

    // Broadcast updated rule hits after each change
    if (entry.verdict?.rule) {
      const rules = Array.from(this.ruleHitCounts.entries()).map(
        ([name, { action, hits }]) => ({ name, action, hits })
      );
      this.broadcast({
        type: "ruleHits",
        ts: new Date().toISOString(),
        payload: { rules },
      });
    }
  }

  // ── Client Message Handling ────────────────────────────────────────

  private handleClientMessage(ws: WebSocket, msg: ClientWsMessage): void {
    switch (msg.type) {
      case "toggleKillSwitch":
        if (this.options.killSwitch) {
          if (this.options.killSwitch.isActive()) {
            this.options.killSwitch.deactivate();
          } else {
            this.options.killSwitch.activate();
          }
          // Broadcast new status
          this.broadcast({
            type: "killSwitch",
            ts: new Date().toISOString(),
            payload: { active: this.options.killSwitch.isActive() },
          });
        }
        break;

      case "getStats":
        this.sendStats(ws);
        break;

      case "getConfig":
        this.sendConfig(ws);
        break;

      case "getAuditLog": {
        const entries = this.options.logger?.getEntries() ?? [];
        let filtered = entries;
        if (msg.filter && msg.filter !== "all") {
          filtered = entries.filter((e) => e.verdict?.action === msg.filter);
        }
        const limited = msg.limit ? filtered.slice(-msg.limit) : filtered.slice(-100);
        this.sendTo(ws, {
          type: "audit",
          ts: new Date().toISOString(),
          payload: limited,
        });
        break;
      }
    }
  }

  // ── Broadcasting ──────────────────────────────────────────────────

  private broadcast(msg: WsMessage): void {
    if (!this.wss) return;
    const data = JSON.stringify(msg);
    for (const ws of this.wss.clients) {
      if (ws.readyState === 1 /* OPEN */) {
        ws.send(data);
      }
    }
  }

  private sendTo(ws: WebSocket, msg: WsMessage): void {
    if (ws.readyState === 1) {
      ws.send(JSON.stringify(msg));
    }
  }

  private broadcastStats(): void {
    if (!this.wss || this.wss.clients.size === 0) return;
    const stats = this.buildStats();
    this.broadcast({
      type: "stats",
      ts: new Date().toISOString(),
      payload: stats,
    });
  }

  private sendStats(ws: WebSocket): void {
    this.sendTo(ws, {
      type: "stats",
      ts: new Date().toISOString(),
      payload: this.buildStats(),
    });
  }

  private buildStats(): StatsPayload {
    const proxyStats = this.options.proxy.getStats();
    return {
      ...proxyStats,
      uptime: Math.floor((Date.now() - this.startTime) / 1000),
      killSwitchActive: this.options.killSwitch?.isActive() ?? false,
    };
  }

  private sendConfig(ws: WebSocket): void {
    const pe = this.options.policyEngine;
    const policyConfig = pe?.getConfig();
    const config: ConfigPayload = {
      defaultAction: policyConfig?.defaultAction ?? "prompt",
      ruleCount: policyConfig?.rules?.length ?? 0,
      mode: policyConfig?.mode ?? "standard",
      security: {
        injection: policyConfig?.security?.injectionDetection?.enabled ?? false,
        egress: policyConfig?.security?.egressControl?.enabled ?? false,
        killSwitch: !!this.options.killSwitch,
        chain: policyConfig?.security?.chainDetection?.enabled ?? false,
        signing: policyConfig?.security?.signing ?? false,
      },
    };
    this.sendTo(ws, {
      type: "config",
      ts: new Date().toISOString(),
      payload: config,
    });
  }

  private sendRuleHits(ws: WebSocket): void {
    const rules = Array.from(this.ruleHitCounts.entries()).map(
      ([name, { action, hits }]) => ({ name, action, hits })
    );
    this.sendTo(ws, {
      type: "ruleHits",
      ts: new Date().toISOString(),
      payload: { rules } as RuleHitsPayload,
    });
  }

  // ── Static File Serving ───────────────────────────────────────────

  private handleHttpRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    staticDir?: string
  ): void {
    if (!staticDir) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end("<html><body><h1>Agent Wall Dashboard</h1><p>No static assets found. Build the dashboard package first.</p></body></html>");
      return;
    }

    const url = req.url?.split("?")[0] ?? "/";
    let filePath = path.join(staticDir, url === "/" ? "index.html" : url);

    // Security: prevent path traversal
    const resolved = path.resolve(filePath);
    if (!resolved.startsWith(path.resolve(staticDir))) {
      res.writeHead(403);
      res.end("Forbidden");
      return;
    }

    // Try to serve the file
    try {
      if (!fs.existsSync(resolved) || fs.statSync(resolved).isDirectory()) {
        // SPA fallback: serve index.html for unknown routes
        filePath = path.join(staticDir, "index.html");
      }

      const content = fs.readFileSync(filePath);
      const ext = path.extname(filePath).toLowerCase();
      const contentType = MIME_TYPES[ext] ?? "application/octet-stream";

      res.writeHead(200, { "Content-Type": contentType });
      res.end(content);
    } catch {
      res.writeHead(404);
      res.end("Not Found");
    }
  }
}
