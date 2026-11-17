import { useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { api, getApiKey, setApiKey } from "../api/client";
import { useAsync } from "../hooks/useAsync";

const NAV = [
  { to: "/", label: "Overview", end: true },
  { to: "/alerts", label: "Alerts" },
  { to: "/events", label: "Events" },
  { to: "/upload", label: "Upload" },
  { to: "/rules", label: "Rules" },
];

export function Layout() {
  const health = useAsync((signal) => api.health(signal), [], 20_000);
  const open = useAsync((signal) => api.alerts({ active: true, size: 1 }, signal), [], 15_000);
  const [editingKey, setEditingKey] = useState(false);
  const [keyDraft, setKeyDraft] = useState(getApiKey());
  const [lookup, setLookup] = useState("");
  const navigate = useNavigate();

  const online = health.data?.status === "ok";
  const openCount = open.data?.total ?? 0;

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <svg width="26" height="26" viewBox="0 0 32 32" aria-hidden="true">
            <path
              d="M16 5l9 3.5v6.6c0 5.3-3.7 9.4-9 11-5.3-1.6-9-5.7-9-11V8.5L16 5z"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinejoin="round"
            />
            <path
              d="M10.5 16h3l1.8-3.5 2.4 7 1.8-3.5h2"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          <span>Mini SIEM</span>
        </div>

        <nav className="nav" aria-label="Main">
          {NAV.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.end} className={({ isActive }) => (isActive ? "active" : "")}>
              {item.label}
              {item.to === "/alerts" && openCount > 0 && <span className="nav-count">{openCount}</span>}
            </NavLink>
          ))}
        </nav>

        <form
          className="lookup"
          onSubmit={(event) => {
            event.preventDefault();
            const address = lookup.trim();
            if (!address) return;
            navigate(`/ips/${encodeURIComponent(address)}`);
            setLookup("");
          }}
        >
          <label className="small muted" htmlFor="ip-lookup">
            Investigate an IP
          </label>
          <input
            id="ip-lookup"
            value={lookup}
            onChange={(event) => setLookup(event.target.value)}
            placeholder="203.0.113.50"
            autoComplete="off"
            spellCheck={false}
          />
        </form>

        <div className="sidebar-foot">
          <div className="status-line">
            <span className={`dot ${online ? "dot-ok" : "dot-bad"}`} aria-hidden="true" />
            {online ? `API online, ${health.data?.rules} rules` : health.error ? "API unreachable" : "Connecting..."}
          </div>
          {editingKey ? (
            <form
              className="keyform"
              onSubmit={(event) => {
                event.preventDefault();
                setApiKey(keyDraft.trim());
                window.location.reload();
              }}
            >
              <label className="small muted" htmlFor="api-key">
                X-API-Key
              </label>
              <input
                id="api-key"
                type="password"
                value={keyDraft}
                onChange={(event) => setKeyDraft(event.target.value)}
                autoComplete="off"
                placeholder="Leave empty for none"
              />
              <button className="btn btn-primary" type="submit">
                Save
              </button>
            </form>
          ) : (
            <button className="btn btn-ghost" onClick={() => setEditingKey(true)}>
              API key
            </button>
          )}
        </div>
      </aside>

      <main className="main">
        <Outlet />
      </main>
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: React.ReactNode }) {
  return (
    <header className="page-header">
      <div>
        <h1>{title}</h1>
        {subtitle && <p className="muted">{subtitle}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}
