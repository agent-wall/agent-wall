import { useDashboard } from "../hooks/useDashboardStore.js";
import { formatNumber } from "../utils/format.js";

export function StatsCards() {
  const { state } = useDashboard();
  const { stats, attacks } = state;

  if (!stats) {
    return (
      <div className="stats-row">
        <div className="card stat-card">
          <div className="stat-label">Waiting for data...</div>
        </div>
      </div>
    );
  }

  const cards = [
    {
      label: "Total",
      value: formatNumber(stats.total),
      color: "var(--text-primary)",
      glow: false,
    },
    {
      label: "Forwarded",
      value: formatNumber(stats.forwarded),
      color: "var(--green)",
      glow: false,
    },
    {
      label: "Denied",
      value: formatNumber(stats.denied),
      color: "var(--red)",
      glow: stats.denied > 0,
    },
    {
      label: "Attacks",
      value: formatNumber(attacks.length),
      color: "var(--orange)",
      glow: attacks.length > 0,
    },
    {
      label: "Scanned",
      value: formatNumber(stats.scanned),
      color: "var(--blue)",
      glow: false,
    },
  ];

  return (
    <div className="stats-row">
      {cards.map((c) => (
        <div key={c.label} className={`card stat-card ${c.glow ? "stat-glow" : ""}`}>
          <div className="stat-label">{c.label}</div>
          <div className="stat-value" style={{ color: c.color }}>
            {c.value}
          </div>
        </div>
      ))}
    </div>
  );
}
