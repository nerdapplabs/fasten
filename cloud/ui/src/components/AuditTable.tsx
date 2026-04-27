import { AuditRow } from '../mock/audit';

interface Props {
  rows: AuditRow[];
  onSelect?: (row: AuditRow) => void;
}

const sevDot: Record<AuditRow['severity'], string> = {
  info: '●',
  warn: '▲',
  error: '✗',
  critical: '✗',
};

export function AuditTable({ rows, onSelect }: Props) {
  return (
    <table className="audit-table">
      <thead>
        <tr>
          <th>time</th>
          <th>code</th>
          <th>actor</th>
          <th>target</th>
          <th>via</th>
          <th>request_id</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {rows.map(r => (
          <tr key={r.id} className={`row sev-${r.severity}`} onClick={() => onSelect?.(r)}>
            <td className="mono dim">{r.ts}</td>
            <td>
              <span className={`code-pill domain-${r.domain}`}>{r.code}</span>
            </td>
            <td>
              <span className="actor">{r.actor}</span>
              <span className="actor-kind">{r.actorKind}</span>
            </td>
            <td className="mono">{r.target}</td>
            <td className="mono dim">{r.method}</td>
            <td className="mono dim">{r.requestId}</td>
            <td className={`sev-glyph sev-${r.severity}`}>{sevDot[r.severity]}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
