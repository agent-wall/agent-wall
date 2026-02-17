import { useState } from "react";
import { useDashboard } from "../hooks/useDashboardStore.js";
import { StatusBadge } from "./StatusBadge.js";

type SortKey = "name" | "action" | "hits";
type SortDir = "asc" | "desc";

export function RuleTable() {
  const { state } = useDashboard();
  const [sortKey, setSortKey] = useState<SortKey>("hits");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const rules = state.ruleHits?.rules ?? [];

  const sorted = [...rules].sort((a, b) => {
    const mul = sortDir === "asc" ? 1 : -1;
    if (sortKey === "hits") return (a.hits - b.hits) * mul;
    return a[sortKey].localeCompare(b[sortKey]) * mul;
  });

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("desc");
    }
  };

  const arrow = (key: SortKey) =>
    sortKey === key ? (sortDir === "asc" ? " ^" : " v") : "";

  if (sorted.length === 0) {
    return <div className="empty-state">No rule activity yet</div>;
  }

  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th onClick={() => handleSort("name")}>Rule{arrow("name")}</th>
            <th onClick={() => handleSort("action")} style={{ width: 90 }}>Action{arrow("action")}</th>
            <th onClick={() => handleSort("hits")} style={{ width: 80 }}>Hits{arrow("hits")}</th>
            <th style={{ width: "40%" }}>Bar</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((rule) => {
            const maxHits = sorted[0]?.hits ?? 1;
            const pct = maxHits > 0 ? (rule.hits / maxHits) * 100 : 0;
            const barColor = rule.action === "deny" ? "var(--red)" : rule.action === "allow" ? "var(--green)" : "var(--yellow)";
            return (
              <tr key={rule.name}>
                <td className="cell-rule-name">{rule.name}</td>
                <td><StatusBadge action={rule.action} /></td>
                <td className="cell-mono">{rule.hits}</td>
                <td>
                  <div className="hit-bar-bg">
                    <div className="hit-bar" style={{ width: `${pct}%`, background: barColor }} />
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
