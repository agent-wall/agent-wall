/**
 * Agent Wall Stdio Proxy
 *
 * The core of Agent Wall. Sits between an MCP client and server,
 * intercepting every JSON-RPC message over stdio (stdin/stdout).
 *
 * Architecture:
 *   MCP Client (e.g. Claude Code)
 *       ↕ stdin/stdout
 *   Agent Wall Proxy (this file)
 *       ↕ stdin/stdout (child process)
 *   MCP Server (e.g. filesystem server)
 *
 * The proxy:
 *   1. Spawns the real MCP server as a child process
 *   2. Reads JSON-RPC from its own stdin (from the MCP client)
 *   3. For tools/call requests: evaluates against the policy engine
 *   4. If allowed: forwards to child's stdin
 *   5. If denied: returns a JSON-RPC error without forwarding
 *   6. Pipes child's stdout back to its own stdout (to the MCP client)
 */

import { type ChildProcess } from "node:child_process";
import spawn from "cross-spawn";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as readline from "node:readline";
import { EventEmitter } from "node:events";
import { ReadBuffer, BufferOverflowError, serializeMessage } from "./read-buffer.js";
import {
  type JsonRpcMessage,
  type JsonRpcRequest,
  type JsonRpcResponse,
  type McpContentBlock,
  isRequest,
  isResponse,
  isToolCall,
  getToolCallParams,
  createDenyResponse,
} from "./types.js";
import { PolicyEngine, type PolicyVerdict } from "./policy-engine.js";
import { AuditLogger, type AuditEntry } from "./audit-logger.js";
import { ResponseScanner, type ScanResult } from "./response-scanner.js";
import { InjectionDetector } from "./injection-detector.js";
import { EgressControl } from "./egress-control.js";
import { KillSwitch } from "./kill-switch.js";
import { ChainDetector } from "./chain-detector.js";

// ── Proxy Options ───────────────────────────────────────────────────

export interface ProxyOptions {
  /** The command to spawn (e.g. "npx") */
  command: string;
  /** Arguments for the command (e.g. ["@modelcontextprotocol/server-filesystem", "/path"]) */
  args?: string[];
  /** Environment variables for the child process */
  env?: Record<string, string>;
  /** Working directory for the child process */
  cwd?: string;
  /** The policy engine instance */
  policyEngine: PolicyEngine;
  /** The response scanner instance (optional — if not provided, responses pass through) */
  responseScanner?: ResponseScanner;
  /** The audit logger instance */
  logger: AuditLogger;
  /** Session ID for audit logging */
  sessionId?: string;
  /** Callback for prompt actions — return true to allow, false to deny */
  onPrompt?: (
    tool: string,
    args: Record<string, unknown>,
    message: string
  ) => Promise<boolean>;
  /** Called when the proxy is ready (child process spawned) */
  onReady?: () => void;
  /** Called when the proxy exits */
  onExit?: (code: number | null) => void;
  /** Called on error */
  onError?: (error: Error) => void;
  /** Maximum buffer size in bytes (default: 10MB) */
  maxBufferSize?: number;
  /** TTL for pending tool calls in ms (default: 30000) — prevents memory leaks */
  pendingCallTtlMs?: number;
  /** Prompt injection detector (optional) */
  injectionDetector?: InjectionDetector;
  /** Egress/SSRF control (optional) */
  egressControl?: EgressControl;
  /** Emergency kill switch (optional) */
  killSwitch?: KillSwitch;
  /** Tool call chain detector (optional) */
  chainDetector?: ChainDetector;
}

// ── Proxy Events ────────────────────────────────────────────────────

export interface ProxyEvents {
  ready: [];
  exit: [code: number | null];
  error: [error: Error];
  denied: [tool: string, message: string];
  allowed: [tool: string];
  prompted: [tool: string, message: string];
  responseBlocked: [tool: string, findings: string];
  responseRedacted: [tool: string, findings: string];
  injectionDetected: [tool: string, summary: string];
  egressBlocked: [tool: string, summary: string];
  killSwitchActive: [tool: string];
  chainDetected: [tool: string, summary: string];
}

// ── Stdio Proxy ─────────────────────────────────────────────────────

/** Default TTL for pending tool calls: 30 seconds */
const DEFAULT_PENDING_CALL_TTL_MS = 30_000;
/** Cleanup interval for expired pending calls: 10 seconds */
const PENDING_CALL_CLEANUP_INTERVAL_MS = 10_000;

export class StdioProxy extends EventEmitter {
  private child: ChildProcess | null = null;
  private clientBuffer: ReadBuffer;
  private serverBuffer: ReadBuffer;
  private options: ProxyOptions;
  private sessionId: string;
  private running = false;
  private stats = { forwarded: 0, denied: 0, prompted: 0, total: 0, scanned: 0, responseBlocked: 0, responseRedacted: 0 };
  /** Track pending tools/call requests by JSON-RPC id, so we can correlate responses */
  private pendingToolCalls = new Map<string | number, { tool: string; args: Record<string, unknown>; timestamp: number }>();
  /** Cleanup timer for expired pending calls */
  private pendingCleanupTimer: ReturnType<typeof setInterval> | null = null;
  private pendingCallTtlMs: number;

  constructor(options: ProxyOptions) {
    super();
    this.options = options;
    const maxBuf = options.maxBufferSize;
    this.clientBuffer = new ReadBuffer(maxBuf);
    this.serverBuffer = new ReadBuffer(maxBuf);
    this.sessionId =
      options.sessionId ?? `ag-${crypto.randomUUID()}`;
    this.pendingCallTtlMs = options.pendingCallTtlMs ?? DEFAULT_PENDING_CALL_TTL_MS;

    // Prevent unhandled 'error' event crash — route to onError callback if set
    this.on("error", (err: Error) => {
      this.options.onError?.(err);
    });
  }

  /**
   * Start the proxy — spawn the child MCP server and begin intercepting.
   */
  async start(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      try {
        this.child = spawn(this.options.command, this.options.args ?? [], {
          stdio: ["pipe", "pipe", "inherit"],
          env: {
            ...process.env,
            ...this.options.env,
          },
          cwd: this.options.cwd,
          shell: false,
          windowsHide: true,
        });

        this.child.on("error", (err) => {
          this.options.onError?.(err);
          this.emit("error", err);
          reject(err);
        });

        this.child.on("spawn", () => {
          this.running = true;
          this.setupPipelines();
          this.startPendingCallCleanup();
          this.options.onReady?.();
          this.emit("ready");
          resolve();
        });

        this.child.on("close", (code) => {
          this.running = false;
          this.options.onExit?.(code);
          this.emit("exit", code);
        });
      } catch (err) {
        reject(err);
      }
    });
  }

  /**
   * Stop the proxy — gracefully shut down the child process.
   * Follows the MCP SDK pattern: stdin.end() → SIGTERM → SIGKILL
   */
  async stop(): Promise<void> {
    if (!this.child) return;

    const child = this.child;
    this.child = null;
    this.running = false;

    const closePromise = new Promise<void>((resolve) => {
      child.once("close", () => resolve());
    });

    // 1. End stdin gracefully
    try {
      child.stdin?.end();
    } catch {
      /* ignore */
    }

    // 2. Wait up to 2s for process to exit
    const timeout = (ms: number) =>
      new Promise<void>((resolve) => {
        const t = setTimeout(resolve, ms);
        t.unref();
      });

    await Promise.race([closePromise, timeout(2000)]);

    // 3. SIGTERM if still alive
    if (child.exitCode === null) {
      try {
        child.kill("SIGTERM");
      } catch {
        /* ignore */
      }
      await Promise.race([closePromise, timeout(2000)]);
    }

    // 4. SIGKILL as last resort
    if (child.exitCode === null) {
      try {
        child.kill("SIGKILL");
      } catch {
        /* ignore */
      }
    }

    this.stopPendingCallCleanup();
    this.pendingToolCalls.clear();
    this.clientBuffer.clear();
    this.serverBuffer.clear();
    this.options.killSwitch?.dispose();
    this.options.chainDetector?.reset();
    this.options.logger.close();
  }

  /**
   * Get proxy statistics.
   */
  getStats() {
    return { ...this.stats };
  }

  /**
   * Wire up the stdin/stdout pipelines with interception.
   */
  private setupPipelines(): void {
    // ── Client → Proxy → Server ──
    process.stdin.on("data", (chunk: Buffer) => {
      try {
        this.clientBuffer.append(chunk);
        this.processClientMessages();
      } catch (err) {
        if (err instanceof BufferOverflowError) {
          this.emit("error", err);
          this.clientBuffer.clear();
        } else {
          this.emit("error", new Error(`Client buffer error: ${err}`));
        }
      }
    });

    process.stdin.on("end", () => {
      this.stop();
    });

    // ── Server → Proxy → Client ──
    this.child?.stdout?.on("data", (chunk: Buffer) => {
      try {
        this.serverBuffer.append(chunk);
        this.processServerMessages();
      } catch (err) {
        if (err instanceof BufferOverflowError) {
          this.emit("error", err);
          this.serverBuffer.clear();
        } else {
          this.emit("error", new Error(`Server buffer error: ${err}`));
        }
      }
    });
  }

  /**
   * Start periodic cleanup of expired pending tool calls.
   */
  private startPendingCallCleanup(): void {
    this.pendingCleanupTimer = setInterval(() => {
      const now = Date.now();
      for (const [id, entry] of this.pendingToolCalls) {
        if (now - entry.timestamp > this.pendingCallTtlMs) {
          this.pendingToolCalls.delete(id);
        }
      }
    }, PENDING_CALL_CLEANUP_INTERVAL_MS);
    this.pendingCleanupTimer.unref();
  }

  /**
   * Stop the pending call cleanup timer.
   */
  private stopPendingCallCleanup(): void {
    if (this.pendingCleanupTimer) {
      clearInterval(this.pendingCleanupTimer);
      this.pendingCleanupTimer = null;
    }
  }

  /**
   * Process buffered messages from the MCP client.
   * This is where policy enforcement happens.
   */
  private processClientMessages(): void {
    try {
      const messages = this.clientBuffer.readAllMessages();
      for (const msg of messages) {
        this.handleClientMessage(msg);
      }
    } catch (err) {
      // Malformed JSON from client — log and continue
      this.emit("error", new Error(`Invalid JSON from client: ${err}`));
    }
  }

  /**
   * Process buffered messages from the MCP server.
   * Applies response scanning before forwarding to the client.
   */
  private processServerMessages(): void {
    try {
      const messages = this.serverBuffer.readAllMessages();
      for (const msg of messages) {
        this.handleServerMessage(msg);
      }
    } catch (err) {
      // Malformed JSON from server — log and continue
      this.emit("error", new Error(`Invalid JSON from server: ${err}`));
    }
  }

  /**
   * Handle a single message from the MCP server.
   * If it's a response to a tools/call we tracked, scan it.
   */
  private handleServerMessage(msg: JsonRpcMessage): void {
    // Only scan responses (not requests/notifications from server)
    if (!isResponse(msg)) {
      this.writeToClient(msg);
      return;
    }

    const response = msg as JsonRpcResponse;
    const pending = this.pendingToolCalls.get(response.id);

    // If we don't have a pending tool call for this id, or no scanner, pass through
    if (!pending || !this.options.responseScanner) {
      if (pending) this.pendingToolCalls.delete(response.id);
      this.writeToClient(msg);
      return;
    }

    // We have a tracked tool call response — scan it
    this.pendingToolCalls.delete(response.id);
    this.stats.scanned++;

    // Scan both successful responses AND error responses (secrets can leak in error.message/error.data)
    const scanResult = response.error
      ? this.options.responseScanner.scan(this.extractErrorText(response))
      : response.result !== undefined
        ? this.options.responseScanner.scanMcpResponse(response.result)
        : null;

    if (!scanResult || scanResult.clean) {
      this.writeToClient(msg);
      return;
    }

    const findingSummary = scanResult.findings
      .map((f) => `${f.pattern}: ${f.message}`)
      .join("; ");

    switch (scanResult.action) {
      case "block": {
        this.stats.responseBlocked++;
        this.options.logger.log({
          timestamp: new Date().toISOString(),
          sessionId: this.sessionId,
          direction: "response",
          method: "tools/call",
          tool: pending.tool,
          arguments: pending.args,
          verdict: { action: "deny", rule: "__response_scanner__", message: `Response blocked: ${findingSummary}` },
        });
        this.emit("responseBlocked", pending.tool, findingSummary);
        // Send error back to client instead of the response
        const errorResponse = createDenyResponse(
          response.id,
          `Response blocked by Agent Wall scanner: ${findingSummary}`
        );
        this.writeToClient(errorResponse);
        break;
      }
      case "redact": {
        this.stats.responseRedacted++;
        this.options.logger.log({
          timestamp: new Date().toISOString(),
          sessionId: this.sessionId,
          direction: "response",
          method: "tools/call",
          tool: pending.tool,
          arguments: pending.args,
          verdict: { action: "allow", rule: "__response_scanner__", message: `Response redacted: ${findingSummary}` },
        });
        this.emit("responseRedacted", pending.tool, findingSummary);
        // Replace the result content with redacted text
        const redacted = this.buildRedactedResponse(response, scanResult);
        this.writeToClient(redacted);
        break;
      }
      default:
        // "pass" findings — forward as-is (informational only)
        this.writeToClient(msg);
        break;
    }
  }

  /**
   * Build a redacted MCP response by replacing text content.
   */
  private buildRedactedResponse(original: JsonRpcResponse, scanResult: ScanResult): JsonRpcResponse {
    if (!scanResult.redactedText || !original.result) {
      return original;
    }

    const result = original.result as Record<string, unknown>;

    // MCP standard: result.content is an array of content blocks
    if (Array.isArray(result.content)) {
      const redactedContent = result.content.map((block: McpContentBlock) => {
        if (block.type === "text" && typeof block.text === "string") {
          return { ...block, text: scanResult.redactedText };
        }
        return block;
      });
      return {
        ...original,
        result: { ...result, content: redactedContent },
      };
    }

    // Fallback: replace the whole result
    return {
      ...original,
      result: { content: [{ type: "text", text: scanResult.redactedText }] },
    };
  }

  /**
   * Handle a single message from the MCP client.
   *
   * Security check order (defense in depth):
   *   1. Kill switch — if active, deny ALL calls immediately
   *   2. Injection detection — scan arguments for prompt injection
   *   3. Egress control — check for blocked URLs/IPs
   *   4. Policy engine — evaluate rules (existing behavior)
   *   5. Chain detection — record call and check for suspicious sequences
   */
  private handleClientMessage(msg: JsonRpcMessage): void {
    this.stats.total++;

    // Only intercept tools/call requests
    if (!isToolCall(msg)) {
      // Pass through all other messages (initialize, tools/list, notifications, etc.)
      this.writeToServer(msg);
      return;
    }

    // It's a tools/call — run security pipeline
    const request = msg as JsonRpcRequest;
    const toolCall = getToolCallParams(request);

    if (!toolCall) {
      // Malformed tools/call — forward anyway (let the server handle it)
      this.writeToServer(msg);
      return;
    }

    const args = toolCall.arguments ?? {};

    // ── 1. Kill switch check ──
    if (this.options.killSwitch?.isActive()) {
      const reason = this.options.killSwitch.getStatus().reason;
      this.emit("killSwitchActive", toolCall.name);
      this.handleDeny(request, toolCall.name, args, {
        action: "deny",
        rule: "__kill_switch__",
        message: `Kill switch active: ${reason}. All tool calls denied.`,
      });
      return;
    }

    // ── 2. Injection detection ──
    if (this.options.injectionDetector) {
      const injection = this.options.injectionDetector.scan(toolCall);
      if (injection.detected && injection.confidence !== "low") {
        this.emit("injectionDetected", toolCall.name, injection.summary);
        this.handleDeny(request, toolCall.name, args, {
          action: "deny",
          rule: "__injection_detector__",
          message: `Prompt injection blocked: ${injection.summary}`,
        });
        return;
      }
    }

    // ── 3. Egress control ──
    if (this.options.egressControl) {
      const egress = this.options.egressControl.check(toolCall);
      if (!egress.allowed) {
        this.emit("egressBlocked", toolCall.name, egress.summary);
        this.handleDeny(request, toolCall.name, args, {
          action: "deny",
          rule: "__egress_control__",
          message: `Egress blocked: ${egress.summary}`,
        });
        return;
      }
    }

    // ── 4. Policy engine — rule evaluation ──
    const verdict = this.options.policyEngine.evaluate(toolCall);

    // ── 5. Chain detection — record this call and check patterns ──
    if (this.options.chainDetector && verdict.action !== "deny") {
      const chain = this.options.chainDetector.record(toolCall);
      if (chain.detected) {
        const critical = chain.matches.some((m) => m.severity === "critical");
        const summary = chain.matches.map((m) => `${m.chain}(${m.severity})`).join(", ");
        this.emit("chainDetected", toolCall.name, summary);
        // Critical chains are blocked, others are logged as warnings
        if (critical) {
          this.handleDeny(request, toolCall.name, args, {
            action: "deny",
            rule: "__chain_detector__",
            message: `Critical tool chain blocked: ${summary}`,
          });
          return;
        }
        // Non-critical chains: log the warning but let the call proceed
        this.options.logger.log({
          timestamp: new Date().toISOString(),
          sessionId: this.sessionId,
          direction: "request",
          method: "tools/call",
          tool: toolCall.name,
          arguments: args,
          verdict: {
            action: "allow",
            rule: "__chain_detector__",
            message: `Suspicious tool chain (warning): ${summary}`,
          },
        });
      }
    }

    switch (verdict.action) {
      case "allow":
        this.handleAllow(request, toolCall.name, args, verdict);
        break;
      case "deny":
        this.handleDeny(request, toolCall.name, args, verdict);
        break;
      case "prompt":
        this.handlePrompt(request, toolCall.name, args, verdict);
        break;
    }
  }

  /**
   * Handle an allowed tool call — forward to server.
   */
  private handleAllow(
    request: JsonRpcRequest,
    tool: string,
    args: Record<string, unknown>,
    verdict: PolicyVerdict
  ): void {
    this.stats.forwarded++;

    // Track this request so we can scan the response when it comes back
    if (this.options.responseScanner) {
      this.pendingToolCalls.set(request.id, { tool, args, timestamp: Date.now() });
    }

    this.options.logger.logAllow(
      this.sessionId,
      tool,
      args,
      verdict.rule,
      verdict.message
    );
    this.emit("allowed", tool);
    this.writeToServer(request);
  }

  /**
   * Handle a denied tool call — return error to client, never forward.
   */
  private handleDeny(
    request: JsonRpcRequest,
    tool: string,
    args: Record<string, unknown>,
    verdict: PolicyVerdict
  ): void {
    this.stats.denied++;
    this.options.logger.logDeny(
      this.sessionId,
      tool,
      args,
      verdict.rule,
      verdict.message
    );
    this.emit("denied", tool, verdict.message);

    // Send error back to client
    const errorResponse = createDenyResponse(request.id, verdict.message);
    this.writeToClient(errorResponse);
  }

  /**
   * Handle a prompt tool call — ask for human approval.
   */
  private async handlePrompt(
    request: JsonRpcRequest,
    tool: string,
    args: Record<string, unknown>,
    verdict: PolicyVerdict
  ): Promise<void> {
    this.emit("prompted", tool, verdict.message);

    if (!this.options.onPrompt) {
      // No prompt handler — deny by default (fail-secure)
      this.handleDeny(request, tool, args, {
        ...verdict,
        action: "deny",
        message: `${verdict.message} (auto-denied: no prompt handler)`,
      });
      return;
    }

    try {
      const approved = await this.options.onPrompt(
        tool,
        args,
        verdict.message
      );

      if (approved) {
        this.handleAllow(request, tool, args, {
          ...verdict,
          action: "allow",
          message: `${verdict.message} (manually approved)`,
        });
      } else {
        this.handleDeny(request, tool, args, {
          ...verdict,
          action: "deny",
          message: `${verdict.message} (manually denied)`,
        });
      }
    } catch (err) {
      // Prompt failed — deny (fail-secure)
      this.handleDeny(request, tool, args, {
        ...verdict,
        action: "deny",
        message: `${verdict.message} (prompt error: ${err})`,
      });
    }
  }

  /**
   * Extract scannable text from a JSON-RPC error response.
   */
  private extractErrorText(response: JsonRpcResponse): string {
    const parts: string[] = [];
    if (response.error?.message) parts.push(response.error.message);
    if (response.error?.data !== undefined) {
      parts.push(typeof response.error.data === "string"
        ? response.error.data
        : JSON.stringify(response.error.data));
    }
    return parts.join("\n");
  }

  /**
   * Write a JSON-RPC message to the MCP server (child's stdin).
   */
  private writeToServer(msg: JsonRpcMessage): void {
    if (!this.child?.stdin?.writable) return;
    const data = serializeMessage(msg);
    this.child.stdin.write(data);
  }

  /**
   * Write a JSON-RPC message to the MCP client (our stdout).
   */
  private writeToClient(msg: JsonRpcMessage): void {
    const data = serializeMessage(msg);
    process.stdout.write(data);
  }
}

/**
 * Create a terminal-based prompt handler.
 *
 * IMPORTANT: stdin/stdout are reserved for MCP JSON-RPC protocol.
 * We open /dev/tty (Unix) or CON (Windows) directly to read from
 * the controlling terminal. This prevents conflicts with the
 * MCP message stream on stdin.
 *
 * Output goes to stderr (safe — MCP only uses stdout).
 */
export function createTerminalPromptHandler(): (
  tool: string,
  args: Record<string, unknown>,
  message: string
) => Promise<boolean> {
  return async (tool, args, message) => {
    // Open the controlling terminal directly.
    // stdin is the MCP protocol pipe — we MUST NOT read from it.
    let ttyFd: number;
    try {
      // Works on Unix, macOS, and MINGW/Git Bash on Windows
      ttyFd = fs.openSync("/dev/tty", "r");
    } catch {
      try {
        // Fallback for native Windows (cmd.exe, PowerShell)
        ttyFd = fs.openSync("CON", "r");
      } catch {
        // No controlling terminal (headless, CI, non-interactive MCP client)
        process.stderr.write(
          "\n[agent-wall] No terminal available for prompt — auto-denying (fail-secure)\n"
        );
        return false;
      }
    }

    const ttyInput = fs.createReadStream("", { fd: ttyFd, autoClose: false });

    const rl = readline.createInterface({
      input: ttyInput,
      output: process.stderr,
    });

    // Show the tool call details on stderr
    process.stderr.write("\n");
    process.stderr.write("╔══════════════════════════════════════════════════╗\n");
    process.stderr.write("║  Agent Wall: Approval Required                   ║\n");
    process.stderr.write("╠══════════════════════════════════════════════════╣\n");
    process.stderr.write(`║  Tool:    ${tool}\n`);
    process.stderr.write(`║  Rule:    ${message}\n`);
    process.stderr.write(`║  Args:    ${JSON.stringify(args, null, 0).slice(0, 120)}\n`);
    process.stderr.write("╚══════════════════════════════════════════════════╝\n");

    return new Promise<boolean>((resolve) => {
      rl.question("  Allow this call? [y/N]: ", (answer) => {
        rl.close();
        ttyInput.destroy();
        try { fs.closeSync(ttyFd); } catch { /* ignore */ }
        resolve(answer.trim().toLowerCase() === "y");
      });
    });
  };
}
