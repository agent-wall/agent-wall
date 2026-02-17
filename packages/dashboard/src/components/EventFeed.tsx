import { useState, useRef, useEffect } from "react";
import { useDashboard } from "../hooks/useDashboardStore.js";
import { StatusBadge } from "./StatusBadge.js";

const EVENT_TO_ACTION: Record<string, string> = {
  allowed: "allow",
  denied: "deny",
  prompted: "prompt",
  responseBlocked: "deny",
  responseRedacted: "prompt",
  injectionDetected: "deny",
  egressBlocked: "deny",
  killSwitchActive: "deny",
  chainDetected: "deny",
};

const EVENT_LABELS: Record<string, string> = {
  injectionDetected: "INJECTION",
  egressBlocked: "EGRESS",
  chainDetected: "CHAIN",
  responseBlocked: "RESP BLOCK",
  responseRedacted: "RESP REDACT",
  killSwitchActive: "KILL SWITCH",
};

export function EventFeed() {
  const { state } = useDashboard();
  const [filter, setFilter] = useState<Set<string>>(new Set(["all"]));
  const [autoScroll, setAutoScroll] = useState(true);
  const [expanded, setExpanded] = useState<number | null>(null);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (autoScroll && listRef.current) {
      listRef.current.scrollTop = 0;
    }
  }, [state.events.length, autoScroll]);

  const toggleFilter = (f: string) => {
    setFilter((prev) => {
      const next = new Set(prev);
      if (f === "all") return new Set(["all"]);
      next.delete("all");
      if (next.has(f)) next.delete(f);
      else next.add(f);
      if (next.size === 0) return new Set(["all"]);
      return next;
    });
  };

  const filtered = filter.has("all")
    ? state.events
    : state.events.filter((e) => {
        const action = EVENT_TO_ACTION[e.event] ?? "info";
        return filter.has(action);
      });

  return (
    <div className="card event-feed">
      <div className="panel-header">
        <h3>Live Events</h3>
        <div className="header-meta">
          <span className="event-counter">{state.events.length}</span>
          <div className="filter-chips">
            {["all", "allow", "deny", "prompt"].map((f) => (
              <span
                key={f}
                className={`chip ${filter.has(f) ? "active" : ""}`}
                onClick={() => toggleFilter(f)}
              >
                {f}
              </span>
            ))}
          </div>
        </div>
      </div>
      <div
        className="event-list"
        ref={listRef}
        onScroll={() => {
          if (listRef.current) {
            setAutoScroll(listRef.current.scrollTop < 10);
          }
        }}
      >
        {filtered.length === 0 ? (
          <div className="empty-state">No events yet</div>
        ) : (
          filtered.map((event, i) => {
            const action = EVENT_TO_ACTION[event.event] ?? "info";
            const tag = EVENT_LABELS[event.event];
            const isExpanded = expanded === i;

            return (
              <div
                key={`${i}-${event.tool}`}
                className={`event-row ${isExpanded ? "event-expanded" : ""} event-anim`}
                onClick={() => setExpanded(isExpanded ? null : i)}
                title={event.detail}
              >
                <span className={`severity-dot severity-${event.severity}`} />
                <StatusBadge action={action} />
                {tag && <span className="event-tag">{tag}</span>}
                <span className="event-tool">{event.tool}</span>
                <span className={`event-detail ${isExpanded ? "event-detail-full" : ""}`}>
                  {event.detail}
                </span>
              </div>
            );
          })
        )}
      </div>
      {!autoScroll && (
        <button
          className="scroll-btn"
          onClick={() => {
            setAutoScroll(true);
            if (listRef.current) listRef.current.scrollTop = 0;
          }}
        >
          Resume auto-scroll
        </button>
      )}
    </div>
  );
}
