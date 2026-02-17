import { useState } from "react";
import { useDashboard } from "../hooks/useDashboardStore.js";
import { formatUptime } from "../utils/format.js";
import { StatsCards } from "./StatsCards.js";
import { EventFeed } from "./EventFeed.js";
import { AttackPanel } from "./AttackPanel.js";
import { RuleTable } from "./RuleTable.js";
import { KillSwitchToggle } from "./KillSwitchToggle.js";
import { AuditSearch } from "./AuditSearch.js";

type Tab = "attacks" | "rules" | "audit";

export function Layout() {
  const { state } = useDashboard();
  const [activeTab, setActiveTab] = useState<Tab>("attacks");

  const tabs: Array<{ key: Tab; label: string; count?: number }> = [
    { key: "attacks", label: "Attacks", count: state.attacks.length },
    { key: "rules", label: "Rules", count: state.ruleHits?.rules?.length ?? 0 },
    { key: "audit", label: "Audit Log", count: state.auditEntries.length },
  ];

  return (
    <div className="dashboard">
      {/* ── Header ── */}
      <header className="dash-header">
        <div className="header-left">
          <h1 className="logo">
            <svg width="22" height="22" viewBox="0 0 64 64" style={{ verticalAlign: "middle", marginRight: 8 }}>
              <path d="M32 4L8 16v16c0 14.4 10.2 27.8 24 32 13.8-4.2 24-17.6 24-32V16L32 4z" fill="#1a73e8" stroke="#0d47a1" strokeWidth="2"/>
              <path d="M32 12l-18 9v12c0 11 7.8 21.2 18 24.4C42.2 54.2 50 44 50 33V21L32 12z" fill="#0d1117"/>
              <path d="M28 30l-4 4 8 8 12-12-4-4-8 8-4-4z" fill="#4caf50"/>
            </svg>
            Agent Wall
          </h1>
          <span className={`connection-dot ${state.connected ? "connected" : "disconnected"}`} />
          <span className="connection-text">
            {state.connected ? "Connected" : "Disconnected"}
          </span>
        </div>
        <div className="header-right">
          {state.stats && (
            <span className="uptime">
              {formatUptime(state.stats.uptime)}
            </span>
          )}
          <KillSwitchToggle />
        </div>
      </header>

      {/* ── Stats ── */}
      <StatsCards />

      {/* ── Event Feed (full width) ── */}
      <EventFeed />

      {/* ── Tabbed Panel ── */}
      <div className="tab-container">
        <div className="tab-bar">
          {tabs.map((t) => (
            <button
              key={t.key}
              className={`tab-btn ${activeTab === t.key ? "tab-active" : ""}`}
              onClick={() => setActiveTab(t.key)}
            >
              {t.label}
              {(t.count ?? 0) > 0 && (
                <span className={`tab-count ${t.key === "attacks" && (t.count ?? 0) > 0 ? "tab-count-alert" : ""}`}>
                  {t.count}
                </span>
              )}
            </button>
          ))}
        </div>
        <div className="tab-content">
          {activeTab === "attacks" && <AttackPanel />}
          {activeTab === "rules" && <RuleTable />}
          {activeTab === "audit" && <AuditSearch />}
        </div>
      </div>
    </div>
  );
}
