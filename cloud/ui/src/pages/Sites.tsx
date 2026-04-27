import { mockSites } from '../mock/audit';

export function Sites() {
  const total = mockSites.reduce((a, s) => a + s.rowsLast24h, 0);
  return (
    <div className="page">
      <div className="page-head">
        <h1>Sites</h1>
        <p className="page-subtitle">{mockSites.length} sites · {mockSites.reduce((a, s) => a + s.nodes, 0)} nodes · {total.toLocaleString()} rows / 24 h</p>
      </div>

      <section className="card no-pad">
        <table className="audit-table">
          <thead>
            <tr>
              <th>site</th>
              <th>region</th>
              <th>nodes</th>
              <th>rows / 24 h</th>
              <th>share</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {mockSites.map(s => {
              const pct = (s.rowsLast24h / total) * 100;
              return (
                <tr key={s.id} className="row">
                  <td><strong>{s.name}</strong> <span className="dim mono">({s.id})</span></td>
                  <td className="mono dim">{s.region}</td>
                  <td className="mono">{s.nodes}</td>
                  <td className="mono">{s.rowsLast24h.toLocaleString()}</td>
                  <td>
                    <div className="bar-cell">
                      <div className="bar" style={{ width: `${pct}%` }} />
                      <span className="bar-label">{pct.toFixed(1)}%</span>
                    </div>
                  </td>
                  <td className="dim">→</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>

      <section className="card highlight-card">
        <div className="card-head"><h2>Add a site</h2><span className="card-aside badge">v0.2</span></div>
        <p>Onboarding flow: install rivet SDK on a node, register the site_id, generate the m2m token, point the SDK at <code>https://api.rivet-cloud.dev/api/v1/audit/ingest</code>.</p>
        <p className="muted">Wired to live API in v0.2.</p>
      </section>
    </div>
  );
}
