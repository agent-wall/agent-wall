/**
 * DashboardServer Tests
 *
 * Tests the WebSocket + HTTP server that bridges proxy events
 * to the browser dashboard.
 */

import { describe, it, expect, beforeAll, afterAll, vi, beforeEach } from "vitest";
import { EventEmitter } from "node:events";
import WebSocket from "ws";
import * as http from "node:http";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { DashboardServer, type WsMessage, type ProxyEventPayload, type StatsPayload } from "./dashboard-server.js";

// ── Mock Proxy ──────────────────────────────────────────────────────

function createMockProxy() {
  const emitter = new EventEmitter();
  (emitter as any).getStats = () => ({
    forwarded: 10,
    denied: 3,
    prompted: 2,
    total: 15,
    scanned: 8,
    responseBlocked: 1,
    responseRedacted: 2,
  });
  return emitter as any;
}

function createMockKillSwitch() {
  let active = false;
  return {
    isActive: () => active,
    activate: () => { active = true; },
    deactivate: () => { active = false; },
  } as any;
}

// ── Helpers ─────────────────────────────────────────────────────────

interface ConnectedWs extends WebSocket {
  _earlyMessages: WsMessage[];
}

function connectWs(port: number): Promise<ConnectedWs> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}`) as ConnectedWs;
    ws._earlyMessages = [];
    // Buffer messages that arrive before test sets up listeners
    const earlyHandler = (data: WebSocket.RawData) => {
      try { ws._earlyMessages.push(JSON.parse(data.toString())); } catch {}
    };
    ws.on("message", earlyHandler);
    ws.on("open", () => {
      // Give server a moment to send initial messages, then resolve
      setTimeout(() => {
        ws.removeListener("message", earlyHandler);
        resolve(ws);
      }, 200);
    });
    ws.on("error", reject);
  });
}

function waitForMessage(ws: WebSocket, type?: string): Promise<WsMessage> {
  return new Promise((resolve) => {
    const handler = (data: WebSocket.RawData) => {
      const msg: WsMessage = JSON.parse(data.toString());
      if (!type || msg.type === type) {
        ws.removeListener("message", handler);
        resolve(msg);
      }
    };
    ws.on("message", handler);
  });
}

function collectMessages(ws: WebSocket, count: number, timeoutMs = 3000): Promise<WsMessage[]> {
  return new Promise((resolve) => {
    const msgs: WsMessage[] = [];
    const handler = (data: WebSocket.RawData) => {
      msgs.push(JSON.parse(data.toString()));
      if (msgs.length >= count) {
        ws.removeListener("message", handler);
        clearTimeout(timer);
        resolve(msgs);
      }
    };
    ws.on("message", handler);
    const timer = setTimeout(() => {
      ws.removeListener("message", handler);
      resolve(msgs);
    }, timeoutMs);
  });
}

function httpGet(port: number, urlPath: string): Promise<{ status: number; body: string; contentType: string }> {
  return new Promise((resolve, reject) => {
    http.get(`http://127.0.0.1:${port}${urlPath}`, (res) => {
      let body = "";
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => {
        resolve({
          status: res.statusCode ?? 500,
          body,
          contentType: res.headers["content-type"] ?? "",
        });
      });
    }).on("error", reject);
  });
}

// ── Tests ───────────────────────────────────────────────────────────

describe("DashboardServer", () => {
  let proxy: ReturnType<typeof createMockProxy>;
  let killSwitch: ReturnType<typeof createMockKillSwitch>;
  let server: DashboardServer;
  let port: number;

  beforeAll(async () => {
    proxy = createMockProxy();
    killSwitch = createMockKillSwitch();
    server = new DashboardServer({
      port: 0, // Random available port
      proxy,
      killSwitch,
      statsIntervalMs: 100, // Fast for testing
    });
    await server.start();
    port = server.getPort();
  });

  afterAll(async () => {
    await server.stop();
  });

  it("should start and listen on a port", () => {
    expect(port).toBeGreaterThan(0);
  });

  it("should send welcome message on WebSocket connection", async () => {
    const ws = await connectWs(port);
    try {
      const welcome = ws._earlyMessages.find((m) => m.type === "welcome");
      expect(welcome).toBeDefined();
      expect(welcome!.ts).toBeDefined();
      expect((welcome!.payload as any).message).toContain("Dashboard connected");
    } finally {
      ws.close();
    }
  });

  it("should send stats on connection", async () => {
    const ws = await connectWs(port);
    try {
      const statsMsg = ws._earlyMessages.find((m) => m.type === "stats");
      expect(statsMsg).toBeDefined();
      const stats = statsMsg!.payload as StatsPayload;
      expect(stats.forwarded).toBe(10);
      expect(stats.denied).toBe(3);
      expect(stats.total).toBe(15);
      expect(stats.uptime).toBeGreaterThanOrEqual(0);
      expect(stats.killSwitchActive).toBe(false);
    } finally {
      ws.close();
    }
  });

  it("should broadcast proxy events to connected clients", async () => {
    const ws = await connectWs(port);
    try {
      // Initial messages already buffered in _earlyMessages

      // Emit a denied event from proxy
      proxy.emit("denied", "read_file", "Access to .ssh blocked");

      const msg = await waitForMessage(ws, "event");
      const payload = msg.payload as ProxyEventPayload;
      expect(payload.event).toBe("denied");
      expect(payload.tool).toBe("read_file");
      expect(payload.detail).toBe("Access to .ssh blocked");
      expect(payload.severity).toBe("warn");
    } finally {
      ws.close();
    }
  });

  it("should broadcast injection events with critical severity", async () => {
    const ws = await connectWs(port);
    try {
      proxy.emit("injectionDetected", "bash", "Role override pattern detected");

      const msg = await waitForMessage(ws, "event");
      const payload = msg.payload as ProxyEventPayload;
      expect(payload.event).toBe("injectionDetected");
      expect(payload.severity).toBe("critical");
    } finally {
      ws.close();
    }
  });

  it("should broadcast stats periodically", async () => {
    const ws = await connectWs(port);
    try {
      // Wait for periodic stats broadcast (interval is 100ms in test)
      const msg = await waitForMessage(ws, "stats");
      expect(msg.type).toBe("stats");
      expect((msg.payload as StatsPayload).total).toBe(15);
    } finally {
      ws.close();
    }
  });

  it("should toggle kill switch via client message", async () => {
    const ws = await connectWs(port);
    try {
      expect(killSwitch.isActive()).toBe(false);

      // Send toggle command
      ws.send(JSON.stringify({ type: "toggleKillSwitch" }));

      const msg = await waitForMessage(ws, "killSwitch");
      expect((msg.payload as any).active).toBe(true);
      expect(killSwitch.isActive()).toBe(true);

      // Toggle back
      ws.send(JSON.stringify({ type: "toggleKillSwitch" }));

      const msg2 = await waitForMessage(ws, "killSwitch");
      expect((msg2.payload as any).active).toBe(false);
      expect(killSwitch.isActive()).toBe(false);
    } finally {
      ws.close();
    }
  });

  it("should handle audit entry and track rule hits", async () => {
    const ws = await connectWs(port);
    try {
      // Simulate audit entries
      server.handleAuditEntry({
        timestamp: new Date().toISOString(),
        sessionId: "test-session",
        direction: "request",
        method: "tools/call",
        tool: "read_file",
        verdict: { action: "deny", rule: "block-ssh-keys", message: "SSH blocked" },
      });

      const msg = await waitForMessage(ws, "audit");
      expect((msg.payload as any).tool).toBe("read_file");
      expect((msg.payload as any).verdict.rule).toBe("block-ssh-keys");
    } finally {
      ws.close();
    }
  });

  it("should broadcast to multiple clients", async () => {
    const ws1 = await connectWs(port);
    const ws2 = await connectWs(port);
    try {
      proxy.emit("allowed", "list_directory");

      const [msg1, msg2] = await Promise.all([
        waitForMessage(ws1, "event"),
        waitForMessage(ws2, "event"),
      ]);

      expect((msg1.payload as ProxyEventPayload).tool).toBe("list_directory");
      expect((msg2.payload as ProxyEventPayload).tool).toBe("list_directory");
    } finally {
      ws1.close();
      ws2.close();
    }
  });

  it("should serve fallback HTML when no staticDir is set", async () => {
    const resp = await httpGet(port, "/");
    expect(resp.status).toBe(200);
    expect(resp.contentType).toContain("text/html");
    expect(resp.body).toContain("Agent Wall Dashboard");
  });

  it("should handle client disconnect without errors", async () => {
    const ws = await connectWs(port);
    ws.close();
    // Wait a moment, then verify server still works
    await new Promise((r) => setTimeout(r, 200));

    // Server should still accept new connections
    const ws2 = await connectWs(port);
    const welcome = ws2._earlyMessages.find((m) => m.type === "welcome");
    expect(welcome).toBeDefined();
    ws2.close();
  });
});

describe("DashboardServer — static file serving", () => {
  let server: DashboardServer;
  let port: number;
  let tmpDir: string;

  beforeAll(async () => {
    tmpDir = path.join(os.tmpdir(), `aw-dash-test-${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.writeFileSync(path.join(tmpDir, "index.html"), "<html><body>Dashboard</body></html>");
    fs.mkdirSync(path.join(tmpDir, "assets"), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, "assets", "app.js"), "console.log('ok')");
    fs.writeFileSync(path.join(tmpDir, "assets", "style.css"), "body { color: white; }");

    const proxy = createMockProxy();
    server = new DashboardServer({
      port: 0,
      proxy,
      staticDir: tmpDir,
      statsIntervalMs: 60000, // Don't spam in static tests
    });
    await server.start();
    port = server.getPort();
  });

  afterAll(async () => {
    await server.stop();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("should serve index.html at /", async () => {
    const resp = await httpGet(port, "/");
    expect(resp.status).toBe(200);
    expect(resp.contentType).toContain("text/html");
    expect(resp.body).toContain("Dashboard");
  });

  it("should serve JS assets with correct MIME type", async () => {
    const resp = await httpGet(port, "/assets/app.js");
    expect(resp.status).toBe(200);
    expect(resp.contentType).toContain("application/javascript");
    expect(resp.body).toContain("console.log");
  });

  it("should serve CSS assets with correct MIME type", async () => {
    const resp = await httpGet(port, "/assets/style.css");
    expect(resp.status).toBe(200);
    expect(resp.contentType).toContain("text/css");
  });

  it("should SPA fallback to index.html for unknown routes", async () => {
    const resp = await httpGet(port, "/some/unknown/path");
    expect(resp.status).toBe(200);
    expect(resp.body).toContain("Dashboard");
  });

  it("should block path traversal attempts", async () => {
    const resp = await httpGet(port, "/../../../etc/passwd");
    // Should get 403 or serve index.html (SPA fallback), not leak files
    expect(resp.body).not.toContain("root:");
  });
});
