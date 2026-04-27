import { Link } from 'react-router-dom';
import { mockSites } from '../mock/audit';

export function Topbar() {
  return (
    <header className="topbar">
      <Link to="/" className="brand">
        <span className="brand-mark">◆</span>
        <span className="brand-name">rivet Cloud</span>
        <span className="brand-tag">v0.1.0-alpha</span>
      </Link>

      <div className="topbar-pickers">
        <label className="picker">
          <span className="picker-label">tenant</span>
          <select defaultValue="acme">
            <option value="acme">acme corp</option>
            <option value="nerdapp" disabled>nerdapplabs (demo only)</option>
          </select>
        </label>
        <label className="picker">
          <span className="picker-label">site</span>
          <select defaultValue={mockSites[0].id}>
            <option value="">All sites</option>
            {mockSites.map(s => (
              <option key={s.id} value={s.id}>{s.name}</option>
            ))}
          </select>
        </label>
      </div>

      <div className="topbar-user">
        <span className="user-name">praveen@nerdapplabs.com</span>
        <span className="user-avatar" aria-hidden="true">P</span>
      </div>
    </header>
  );
}
