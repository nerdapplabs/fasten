// rivet Cloud — v0.1 mock UI.
// Real backend wiring lands in v0.2; data here is mock/audit.ts.

import { Routes, Route } from 'react-router-dom';
import { Topbar } from './components/Topbar';
import { Sidebar } from './components/Sidebar';
import { Home } from './pages/Home';
import { Audit } from './pages/Audit';
import { Sites } from './pages/Sites';

export function App() {
  return (
    <div className="app">
      <Topbar />
      <div className="shell">
        <Sidebar />
        <main className="main">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/sites" element={<Sites />} />
            <Route path="/reports" element={<Placeholder title="Compliance reports" version="v1" desc="HIPAA / SOC 2 / GDPR / GMP / ISO 26262 / FSSC 22000 / SOX. Parameterised report templates that run against the cold tier and produce a signed PDF + CSV evidence pack. See rivet-cloud.md §6." />} />
            <Route path="/archive" element={<Placeholder title="Tamper-evident archive" version="v1" desc="WORM storage with chained hashing; daily seal published to a transparency log. Required for FDA Title 21 §11 / GMP integrity claims. See rivet-cloud.md §3.3." />} />
            <Route path="/investigate" element={<Placeholder title="Root-Cause Investigator (5 Whys)" version="v1.3" desc="Walk-the-trail UI on top of cold-tier audit data. Modelled on Toyota Production System / Lean. See rivet-cloud.md §13." />} />
            <Route path="/settings" element={<Placeholder title="Settings" version="v0.2" desc="Tenant + site admin, m2m tokens, RBAC, SSO config." />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

function Placeholder({ title, version, desc }: { title: string; version: string; desc: string }) {
  return (
    <div className="page">
      <div className="page-head">
        <h1>{title} <span className="badge inline-badge">{version}</span></h1>
        <p className="page-subtitle">Planned feature</p>
      </div>
      <div className="card highlight-card"><p>{desc}</p></div>
    </div>
  );
}
