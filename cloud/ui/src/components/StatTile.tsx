interface StatTileProps {
  label: string;
  value: string | number;
  delta?: string;
  hint?: string;
}

export function StatTile({ label, value, delta, hint }: StatTileProps) {
  return (
    <div className="stat-tile">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {delta && <div className="stat-delta">{delta}</div>}
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  );
}
