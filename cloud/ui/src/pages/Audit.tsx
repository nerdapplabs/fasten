import { useMemo, useState } from 'react';
import { AuditTable } from '../components/AuditTable';
import { AuditRow, makeRows, Domain, Severity } from '../mock/audit';

const DOMAINS: Domain[] = ['user', 'commerce', 'config', 'agent', 'fleet'];
const SEVERITIES: Severity[] = ['info', 'warn', 'error', 'critical'];

export function Audit() {
  const rows = useMemo(() => makeRows(64), []);
  const [q, setQ] = useState('');
  const [domain, setDomain] = useState<Domain | ''>('');
  const [severity, setSeverity] = useState<Severity | ''>('');
  const [selected, setSelected] = useState<AuditRow | null>(null);

  const filtered = rows.filter(r => {
    if (q && !`${r.code} ${r.actor} ${r.target} ${r.requestId}`.toLowerCase().includes(q.toLowerCase())) return false;
    if (domain && r.domain !== domain) return false;
    if (severity && r.severity !== severity) return false;
    return true;
  });

  return (
    <div className="page audit-page">
      <div className="page-head">
        <h1>Audit search</h1>
        <p className="page-subtitle">{filtered.length} of {rows.length} rows · all sites</p>
      </div>

      <section className="filter-bar">
        <input
          className="search"
          type="search"
          placeholder="search code, actor, target, request_id…"
          value={q}
          onChange={e => setQ(e.target.value)}
        />
        <select value={domain} onChange={e => setDomain(e.target.value as Domain | '')}>
          <option value="">all domains</option>
          {DOMAINS.map(d => <option key={d} value={d}>{d}</option>)}
        </select>
        <select value={severity} onChange={e => setSeverity(e.target.value as Severity | '')}>
          <option value="">any severity</option>
          {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <button className="btn-ghost" onClick={() => { setQ(''); setDomain(''); setSeverity(''); }}>
          clear
        </button>
      </section>

      <div className={`audit-layout ${selected ? 'with-detail' : ''}`}>
        <section className="card no-pad">
          <AuditTable rows={filtered} onSelect={setSelected} />
        </section>

        {selected && (
          <aside className="detail-panel">
            <div className="detail-head">
              <button className="btn-icon" onClick={() => setSelected(null)} aria-label="close">×</button>
              <h2>Row detail</h2>
            </div>
            <dl className="detail-grid">
              <dt>code</dt>
              <dd><span className={`code-pill domain-${selected.domain}`}>{selected.code}</span></dd>
              <dt>severity</dt>
              <dd className={`sev-${selected.severity}`}>{selected.severity}</dd>
              <dt>timestamp</dt>
              <dd className="mono">{selected.fullTs}</dd>
              <dt>actor</dt>
              <dd>{selected.actor} <span className="actor-kind">{selected.actorKind}</span></dd>
              <dt>target</dt>
              <dd className="mono">{selected.target}</dd>
              <dt>via (method)</dt>
              <dd className="mono">{selected.method}</dd>
              <dt>request_id</dt>
              <dd className="mono">{selected.requestId}</dd>
              {selected.detail && Object.entries(selected.detail).map(([k, v]) => (
                <div key={k} style={{ display: 'contents' }}>
                  <dt className="dim">detail.{k}</dt>
                  <dd className="mono dim">{String(v)}</dd>
                </div>
              ))}
            </dl>
            <div className="detail-foot">
              <button className="btn-primary">Pull full trail</button>
              <span className="muted">v0.2 → calls /api/v1/audit/trail?request_id={selected.requestId}</span>
            </div>
          </aside>
        )}
      </div>
    </div>
  );
}
