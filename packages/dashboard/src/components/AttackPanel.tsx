import { useState } from "react";
import { useDashboard } from "../hooks/useDashboardStore.js";

const CATEGORIES: Array<{
  key: string;
  label: string;
  events: string[];
  color: string;
  icon: string;
}> = [
  {
    key: "injection",
    label: "Prompt Injections",
    events: ["injectionDetected"],
    color: "var(--red)",
    icon: "//",
  },
  {
    key: "egress",
    label: "Egress / SSRF",
    events: ["egressBlocked"],
    color: "var(--orange)",
    icon: "->",
  },
  {
    key: "chain",
    label: "Chain Attacks",
    events: ["chainDetected"],
    color: "var(--yellow)",
    icon: ">>",
  },
  {
    key: "response",
    label: "Response Threats",
    events: ["responseBlocked", "responseRedacted"],
    color: "var(--blue)",
    icon: "<-",
  },
  {
    key: "killswitch",
    label: "Kill Switch",
    events: ["killSwitchActive"],
    color: "var(--red)",
    icon: "!!",
  },
];

export function AttackPanel() {
  const { state } = useDashboard();
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  const toggle = (key: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  if (state.attacks.length === 0) {
    return <div className="empty-state">No attacks detected yet</div>;
  }

  return (
    <div className="attack-list-full">
      {CATEGORIES.map(({ key, label, events, color, icon }) => {
        const items = state.attacks.filter((a) => events.includes(a.event));
        if (items.length === 0) return null;
        const isCollapsed = collapsed.has(key);

        return (
          <div key={key} className="attack-category">
            <div
              className="attack-category-header"
              onClick={() => toggle(key)}
            >
              <span className="attack-icon" style={{ color }}>{icon}</span>
              <span className="attack-label" style={{ color }}>{label}</span>
              <span className="attack-category-count">{items.length}</span>
              <span className="collapse-icon">{isCollapsed ? "+" : "-"}</span>
            </div>
            {!isCollapsed && (
              <div className="attack-items">
                {items.slice(0, 50).map((item, i) => (
                  <div key={i} className="attack-item">
                    <span className={`severity-dot severity-${item.severity}`} />
                    <span className="attack-item-tool">{item.tool}</span>
                    <span className="attack-item-detail">{item.detail}</span>
                  </div>
                ))}
                {items.length > 50 && (
                  <div className="attack-more">+{items.length - 50} more</div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
