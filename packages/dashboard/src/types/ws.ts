/**
 * WebSocket message types — mirrored from @agent-wall/core dashboard-server.ts
 * Keep in sync with packages/core/src/dashboard-server.ts
 */

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

export interface AuditEntry {
  timestamp: string;
  sessionId: string;
  direction: "request" | "response";
  method: string;
  tool?: string;
  arguments?: Record<string, unknown>;
  verdict?: {
    action: "allow" | "deny" | "prompt";
    rule: string | null;
    message: string;
  };
  responsePreview?: string;
  latencyMs?: number;
  error?: string;
}

export type ClientWsMessage =
  | { type: "toggleKillSwitch" }
  | { type: "getStats" }
  | { type: "getConfig" }
  | { type: "getAuditLog"; limit?: number; filter?: string };
