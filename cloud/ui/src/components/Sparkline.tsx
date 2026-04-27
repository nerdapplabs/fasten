interface SparklineProps {
  data: number[];
  width?: number;
  height?: number;
  label?: string;
}

export function Sparkline({ data, width = 600, height = 80, label }: SparklineProps) {
  if (!data.length) return null;
  const max = Math.max(...data, 1);
  const points = data
    .map((v, i) => {
      const x = (i / (data.length - 1)) * width;
      const y = height - (v / max) * (height - 4) - 2;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');

  // Bars below the line for visual density
  const barWidth = width / data.length;

  return (
    <div className="sparkline">
      {label && <div className="sparkline-label">{label}</div>}
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none">
        {data.map((v, i) => {
          const x = (i / (data.length - 1)) * width;
          const h = (v / max) * (height - 4);
          return (
            <rect
              key={i}
              x={x - barWidth / 2 + 1}
              y={height - h - 2}
              width={Math.max(1, barWidth - 2)}
              height={h}
              fill="var(--accent-soft)"
            />
          );
        })}
        <polyline
          points={points}
          fill="none"
          stroke="var(--accent)"
          strokeWidth="1.5"
          strokeLinejoin="round"
        />
      </svg>
      <div className="sparkline-axis">
        <span>60 min ago</span>
        <span className="muted">peak {max} rows/min</span>
        <span>now</span>
      </div>
    </div>
  );
}
