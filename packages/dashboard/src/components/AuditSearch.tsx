import { useState, useEffect } from "react";
import { useDashboard } from "../hooks/useDashboardStore.js";
import { formatTime } from "../utils/format.js";
import { StatusBadge } from "./StatusBadge.js";

export function AuditSearch() {
  const { state, sendMessage } = useDashboard();
  const [search, setSearch] = useState("");
  const [actionFilter, setActionFilter] = useState("all");
  const [loaded, setLoaded] = useState(false);

  // Auto-load on first mount
  useEffect(() => {
    if (!loaded) {
      sendMessage({ type: "getAuditLog", limit: 200 });
      setLoaded(true);
    }
  }, [loaded, sendMessage]);

  const filtered = state.auditEntries.filter((entry) => {
    if (search) {
      const text = `${entry.tool ?? ""} ${entry.verdict?.message ?? ""} ${entry.verdict?.rule ?? ""} ${JSON.stringify(entry.arguments ?? {})}`.toLowerCase();
      if (!text.includes(search.toLowerCase())) return false;
    }
    if (actionFilter !== "all" && entry.verdict?.action !== actionFilter) {
      return false;
    }
    return true;
  });

  return (
    <div className="audit-full">
      <div className="audit-controls">
        <input
          type="text"
          placeholder="Search tool, arguments, rule, message..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select
          value={actionFilter}
          onChange={(e) => setActionFilter(e.target.value)}
          className="audit-select"
        >
          <option value="all">All</option>
          <option value="allow">Allow</option>
          <option value="deny">Deny</option>
          <option value="prompt">Prompt</option>
        </select>
        <button onClick={() => sendMessage({ type: "getAuditLog", limit: 200 })}>
          Refresh
        </button>
      </div>
      <div className="table-scroll">
        {filtered.length === 0 ? (
          <div className="empty-state">
            {state.auditEntries.length === 0
              ? "Waiting for audit entries..."
              : "No matching entries"}
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th style={{ width: 80 }}>Time</th>
                <th style={{ width: 140 }}>Tool</th>
                <th style={{ width: 70 }}>Verdict</th>
                <th style={{ width: 160 }}>Rule</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>
              {filtered.slice(-100).reverse().map((entry, i) => (
                <tr key={i}>
                  <td className="cell-mono">{formatTime(entry.timestamp)}</td>
                  <td className="cell-tool">{entry.tool ?? "-"}</td>
                  <td>
                    {entry.verdict ? (
                      <StatusBadge action={entry.verdict.action} />
                    ) : (
                      "-"
                    )}
                  </td>
                  <td className="cell-rule">{entry.verdict?.rule ?? "-"}</td>
                  <td className="cell-msg" title={entry.verdict?.message ?? ""}>
                    {entry.verdict?.message ?? ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
