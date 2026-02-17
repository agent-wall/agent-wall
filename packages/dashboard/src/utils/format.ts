/** Format seconds as human-readable uptime (e.g., "2h 14m") */
export function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60) % 60;
  const h = Math.floor(seconds / 3600);
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

/** Format a number with comma separators */
export function formatNumber(n: number): string {
  return n.toLocaleString("en-US");
}

/** Format a percentage (e.g., 23.5%) */
export function formatPercent(value: number, total: number): string {
  if (total === 0) return "0%";
  return `${((value / total) * 100).toFixed(1)}%`;
}

/** Format ISO timestamp as HH:MM:SS */
export function formatTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString("en-US", { hour12: false });
}

/** Relative time (e.g., "2m ago", "<1s ago") */
export function timeAgo(iso: string): string {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (diff < 1) return "<1s ago";
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}
