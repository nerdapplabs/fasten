import { useMemo } from 'react';
import { Sparkline } from '../components/Sparkline';
import { StatTile } from '../components/StatTile';
import { AuditTable } from '../components/AuditTable';
import { makeRows, makeActivity, mockSites } from '../mock/audit';
import { Link } from 'react-router-dom';

export function Home() {
  const rows = useMemo(() => makeRows(12), []);
  const activity = useMemo(() => makeActivity(), []);
  const totalRows = activity.reduce((a, b) => a + b, 0);
  const peakSite = mockSites.reduce((a, b) => (a.rowsLast24h > b.rowsLast24h ? a : b));

  return (
    <div className="page">
      <div className="page-head">
        <h1>Audit overview</h1>
        <p className="page-subtitle">Live across <strong>{mockSites.length}</strong> sites · {mockSites.reduce((a, s) => a + s.nodes, 0)} nodes</p>
      </div>

      <section className="stats-row">
        <StatTile label="Rows / past hour" value={totalRows.toLocaleString()} delta="+8.4% vs prev hour" />
        <StatTile label="Active actors" value={38} delta="+2 today" />
        <StatTile label="Distinct codes" value={127} hint="across all domains" />
        <StatTile label="Errors / past hour" value={3} hint="2× PAYMENT_FAILED, 1× POLICY_DENIED" />
      </section>

      <section className="card">
        <div className="card-head">
          <h2>Activity — past 60 minutes</h2>
          <span className="card-aside muted">rows per minute · all sites</span>
        </div>
        <Sparkline data={activity} width={1080} height={120} />
      </section>

      <section className="card">
        <div className="card-head">
          <h2>Recent rows</h2>
          <Link to="/audit" className="card-aside">Open search →</Link>
        </div>
        <AuditTable rows={rows} />
      </section>

      <section className="grid-2">
        <div className="card">
          <div className="card-head">
            <h2>Top sites</h2>
            <span className="card-aside muted">past 24 h</span>
          </div>
          <table className="mini-table">
            <tbody>
              {mockSites.map(s => (
                <tr key={s.id}>
                  <td>{s.name}</td>
                  <td className="mono dim">{s.region}</td>
                  <td className="mono">{s.nodes} nodes</td>
                  <td className="mono dim">{s.rowsLast24h.toLocaleString()} rows</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="card-foot muted">Peak: <strong>{peakSite.name}</strong> ({peakSite.rowsLast24h.toLocaleString()} rows)</div>
        </div>

        <div className="card highlight-card">
          <div className="card-head">
            <h2>Coming in v1.3 · Root-Cause Investigator</h2>
            <span className="card-aside badge">v1.3</span>
          </div>
          <p>5 Whys walk-the-trail UI on top of the cold-tier audit data. Operator picks a symptom, rivet auto-pulls the causal trail, drills down branch by branch.</p>
          <p className="muted">Built for the Lean / Toyota Production System workflow. <a href="../../rivet-cloud.md">See spec §13 →</a></p>
        </div>
      </section>
    </div>
  );
}
