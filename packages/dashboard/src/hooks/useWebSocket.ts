import { useEffect, useRef, useCallback } from "react";
import type { Dispatch } from "react";
import type { DashboardAction } from "./useDashboardStore.js";
import type { WsMessage, ProxyEventPayload, StatsPayload, RuleHitsPayload, ConfigPayload, AuditEntry } from "../types/ws.js";

const RECONNECT_DELAY = 2000;

export function useWebSocket(
  url: string,
  dispatch: Dispatch<DashboardAction>
): (msg: unknown) => void {
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  const sendMessage = useCallback((msg: unknown) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(msg));
    }
  }, []);

  useEffect(() => {
    let disposed = false;

    function connect() {
      if (disposed) return;

      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        dispatch({ type: "WS_CONNECTED" });
      };

      ws.onclose = () => {
        dispatch({ type: "WS_DISCONNECTED" });
        wsRef.current = null;
        if (!disposed) {
          reconnectRef.current = setTimeout(connect, RECONNECT_DELAY);
        }
      };

      ws.onerror = () => {
        // onclose will fire after onerror
      };

      ws.onmessage = (e) => {
        try {
          const msg: WsMessage = JSON.parse(e.data);
          switch (msg.type) {
            case "event":
              dispatch({ type: "EVENT", payload: msg.payload as ProxyEventPayload });
              break;
            case "stats":
              dispatch({ type: "STATS", payload: msg.payload as StatsPayload });
              break;
            case "ruleHits":
              dispatch({ type: "RULE_HITS", payload: msg.payload as RuleHitsPayload });
              break;
            case "killSwitch":
              dispatch({ type: "KILL_SWITCH", payload: msg.payload as { active: boolean } });
              break;
            case "config":
              dispatch({ type: "CONFIG", payload: msg.payload as ConfigPayload });
              break;
            case "audit":
              if (Array.isArray(msg.payload)) {
                dispatch({ type: "AUDIT_ENTRIES", payload: msg.payload as AuditEntry[] });
              } else {
                dispatch({ type: "AUDIT_ENTRY", payload: msg.payload as AuditEntry });
              }
              break;
            // welcome is informational — no action needed
          }
        } catch {
          // Ignore malformed messages
        }
      };
    }

    connect();

    return () => {
      disposed = true;
      clearTimeout(reconnectRef.current);
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, [url, dispatch]);

  return sendMessage;
}
