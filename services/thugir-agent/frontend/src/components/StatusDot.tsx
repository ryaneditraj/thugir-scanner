interface StatusDotProps {
  tone?: "idle" | "ok" | "warn" | "danger" | "running";
  label: string;
}

export function StatusDot({ tone = "idle", label }: StatusDotProps) {
  return (
    <span className={`status-dot status-dot-${tone}`}>
      <span aria-hidden="true" />
      {label}
    </span>
  );
}
