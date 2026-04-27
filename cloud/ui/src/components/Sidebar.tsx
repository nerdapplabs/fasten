import { NavLink } from 'react-router-dom';

export function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-group">
        <span className="sidebar-label">Audit</span>
        <NavLink to="/" end>Home</NavLink>
        <NavLink to="/audit">Search</NavLink>
        <NavLink to="/sites">Sites</NavLink>
      </div>
      <div className="sidebar-group">
        <span className="sidebar-label">Cloud</span>
        <NavLink to="/reports" className="muted-link">Reports <span className="badge">v1</span></NavLink>
        <NavLink to="/archive" className="muted-link">Archive <span className="badge">v1</span></NavLink>
        <NavLink to="/investigate" className="muted-link">Investigator <span className="badge">v1.3</span></NavLink>
      </div>
      <div className="sidebar-group">
        <span className="sidebar-label">Admin</span>
        <NavLink to="/settings" className="muted-link">Settings <span className="badge">v0.2</span></NavLink>
      </div>
      <div className="sidebar-foot">
        <a href="https://github.com/nerdapplabs/EdgeBits" target="_blank" rel="noreferrer">GitHub ↗</a>
        <a href="../../website/docs/" target="_blank" rel="noreferrer">Docs ↗</a>
      </div>
    </aside>
  );
}
