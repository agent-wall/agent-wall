/**
 * @agent-wall/core
 *
 * Core proxy engine and policy evaluator for Agent Wall.
 * "Cloudflare for AI agents" — intercepts MCP tool calls,
 * enforces policies, blocks attacks, logs everything.
 */

// ── Types ───────────────────────────────────────────────────────────
export {
  type JsonRpcMessage,
  type JsonRpcRequest,
  type JsonRpcResponse,
  type JsonRpcNotification,
  type ToolCallParams,
  type ToolListResult,
  type McpContentBlock,
  JsonRpcMessageSchema,
  JsonRpcRequestSchema,
  JsonRpcResponseSchema,
  JsonRpcNotificationSchema,
  isRequest,
  isResponse,
  isNotification,
  isToolCall,
  isToolList,
  getToolCallParams,
  createDenyResponse,
  createPromptResponse,
} from "./types.js";

// ── Read Buffer ─────────────────────────────────────────────────────
export {
  ReadBuffer,
  BufferOverflowError,
  serializeMessage,
  deserializeMessage,
} from "./read-buffer.js";

// ── Policy Engine ───────────────────────────────────────────────────
export {
  PolicyEngine,
  type PolicyConfig,
  type PolicyRule,
  type PolicyVerdict,
  type RuleAction,
  type PolicyMode,
  type RuleMatch,
  type RateLimitConfig,
  type ResponseScannerPolicyConfig,
  type SecurityConfig,
} from "./policy-engine.js";

// ── Policy Loader ───────────────────────────────────────────────────
export {
  loadPolicy,
  loadPolicyFile,
  parsePolicyYaml,
  discoverPolicyFile,
  getDefaultPolicy,
  generateDefaultConfigYaml,
} from "./policy-loader.js";

// ── Response Scanner ────────────────────────────────────────────────
export {
  ResponseScanner,
  createDefaultScanner,
  isRegexSafe,
  type ResponseScannerConfig,
  type ResponsePattern,
  type ResponseAction,
  type ScanResult,
  type ScanFinding,
} from "./response-scanner.js";

// ── Audit Logger ────────────────────────────────────────────────────
export {
  AuditLogger,
  checkFilePermissions,
  type AuditEntry,
  type SignedAuditEntry,
  type AuditLoggerOptions,
  type FilePermissionCheckResult,
} from "./audit-logger.js";

// ── Proxy ───────────────────────────────────────────────────────────
export {
  StdioProxy,
  createTerminalPromptHandler,
  type ProxyOptions,
  type ProxyEvents,
} from "./proxy.js";

// ── Injection Detector ──────────────────────────────────────────────
export {
  InjectionDetector,
  type InjectionDetectorConfig,
  type InjectionScanResult,
  type InjectionMatch,
} from "./injection-detector.js";

// ── Egress Control ──────────────────────────────────────────────────
export {
  EgressControl,
  type EgressControlConfig,
  type EgressCheckResult,
  type EgressUrlInfo,
} from "./egress-control.js";

// ── Kill Switch ─────────────────────────────────────────────────────
export {
  KillSwitch,
  type KillSwitchConfig,
  type KillSwitchStatus,
} from "./kill-switch.js";

// ── Chain Detector ──────────────────────────────────────────────────
export {
  ChainDetector,
  type ChainDetectorConfig,
  type ChainDetectionResult,
  type ChainMatchInfo,
  type ChainPattern,
} from "./chain-detector.js";

// ── Dashboard Server ───────────────────────────────────────────────
export {
  DashboardServer,
  type DashboardServerOptions,
  type WsMessage,
  type WsMessageType,
  type ProxyEventPayload,
  type StatsPayload,
  type RuleHitsPayload,
  type ConfigPayload,
  type ClientWsMessage,
} from "./dashboard-server.js";
