import {
  createContext,
  useContext,
  useReducer,
  type Dispatch,
  type ReactNode,
} from "react";
import React from "react";
import type {
  ProxyEventPayload,
  StatsPayload,
  RuleHitsPayload,
  ConfigPayload,
  AuditEntry,
} from "../types/ws.js";

// ── State ───────────────────────────────────────────────────────────

const MAX_EVENTS = 500;
const MAX_ATTACKS = 200;

export interface DashboardState {
  connected: boolean;
  stats: StatsPayload | null;
  events: ProxyEventPayload[];
  attacks: ProxyEventPayload[];
  ruleHits: RuleHitsPayload | null;
  config: ConfigPayload | null;
  killSwitchActive: boolean;
  auditEntries: AuditEntry[];
}

export const initialState: DashboardState = {
  connected: false,
  stats: null,
  events: [],
  attacks: [],
  ruleHits: null,
  config: null,
  killSwitchActive: false,
  auditEntries: [],
};

// ── Actions ─────────────────────────────────────────────────────────

const ATTACK_EVENTS = new Set([
  "injectionDetected",
  "egressBlocked",
  "chainDetected",
  "responseBlocked",
  "killSwitchActive",
]);

export type DashboardAction =
  | { type: "WS_CONNECTED" }
  | { type: "WS_DISCONNECTED" }
  | { type: "EVENT"; payload: ProxyEventPayload }
  | { type: "STATS"; payload: StatsPayload }
  | { type: "RULE_HITS"; payload: RuleHitsPayload }
  | { type: "KILL_SWITCH"; payload: { active: boolean } }
  | { type: "CONFIG"; payload: ConfigPayload }
  | { type: "AUDIT_ENTRIES"; payload: AuditEntry[] }
  | { type: "AUDIT_ENTRY"; payload: AuditEntry };

export function dashboardReducer(
  state: DashboardState,
  action: DashboardAction
): DashboardState {
  switch (action.type) {
    case "WS_CONNECTED":
      return { ...state, connected: true };

    case "WS_DISCONNECTED":
      return { ...state, connected: false };

    case "EVENT": {
      const newEvents = [action.payload, ...state.events].slice(0, MAX_EVENTS);
      const isAttack = ATTACK_EVENTS.has(action.payload.event);
      const newAttacks = isAttack
        ? [action.payload, ...state.attacks].slice(0, MAX_ATTACKS)
        : state.attacks;
      return { ...state, events: newEvents, attacks: newAttacks };
    }

    case "STATS":
      return {
        ...state,
        stats: action.payload,
        killSwitchActive: action.payload.killSwitchActive,
      };

    case "RULE_HITS":
      return { ...state, ruleHits: action.payload };

    case "KILL_SWITCH":
      return { ...state, killSwitchActive: action.payload.active };

    case "CONFIG":
      return { ...state, config: action.payload };

    case "AUDIT_ENTRIES":
      return { ...state, auditEntries: action.payload };

    case "AUDIT_ENTRY":
      return {
        ...state,
        auditEntries: [...state.auditEntries, action.payload].slice(-500),
      };

    default:
      return state;
  }
}

// ── Context ─────────────────────────────────────────────────────────

interface DashboardContextValue {
  state: DashboardState;
  dispatch: Dispatch<DashboardAction>;
  sendMessage: (msg: unknown) => void;
}

const DashboardContext = createContext<DashboardContextValue | null>(null);

export function useDashboard(): DashboardContextValue {
  const ctx = useContext(DashboardContext);
  if (!ctx) throw new Error("useDashboard must be within DashboardProvider");
  return ctx;
}

export function DashboardProvider({
  children,
  sendMessage,
}: {
  children: ReactNode;
  sendMessage: (msg: unknown) => void;
}) {
  const [state, dispatch] = useReducer(dashboardReducer, initialState);

  return React.createElement(
    DashboardContext.Provider,
    { value: { state, dispatch, sendMessage } },
    children
  );
}

export { DashboardContext };
