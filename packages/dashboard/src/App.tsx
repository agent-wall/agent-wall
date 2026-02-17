import { useReducer, useMemo } from "react";
import React from "react";
import { dashboardReducer, initialState, DashboardContext } from "./hooks/useDashboardStore.js";
import { useWebSocket } from "./hooks/useWebSocket.js";
import { Layout } from "./components/Layout.js";

/**
 * Derive WebSocket URL.
 * - Uses 127.0.0.1 instead of localhost to bypass system proxies
 * - Supports ?ws=<url> query parameter override
 */
function getWsUrl(): string {
  const params = new URLSearchParams(window.location.search);
  const override = params.get("ws");
  if (override) return override;

  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  // Use 127.0.0.1 to bypass proxy for localhost
  const host = window.location.hostname === "localhost"
    ? `127.0.0.1:${window.location.port}`
    : window.location.host;
  return `${proto}//${host}`;
}

export function App() {
  const [state, dispatch] = useReducer(dashboardReducer, initialState);

  const wsUrl = useMemo(() => getWsUrl(), []);
  const sendMessage = useWebSocket(wsUrl, dispatch);

  // Single context — state from this useReducer is THE source of truth
  return React.createElement(
    DashboardContext.Provider,
    { value: { state, dispatch, sendMessage } },
    React.createElement(Layout)
  );
}
