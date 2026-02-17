interface StatusBadgeProps {
  action: string;
  label?: string;
}

export function StatusBadge({ action, label }: StatusBadgeProps) {
  const cls =
    action === "allow" ? "badge-allow" :
    action === "deny" ? "badge-deny" :
    action === "prompt" ? "badge-prompt" :
    "badge-info";

  return <span className={`badge ${cls}`}>{label ?? action}</span>;
}
