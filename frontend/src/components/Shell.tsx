import { Bell, ChevronLeft, ChevronRight, CircleUserRound, FlaskConical, LayoutDashboard, ListFilter, Network, Search, Settings, ShieldAlert, Sparkles, Target, Workflow, BrainCircuit } from "lucide-react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../services/api";
import { useApi } from "../hooks/useApi";
import { useAuth } from "../auth/AuthContext";
import { NavLink as RouterNavLink } from "react-router-dom";

const items = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/alerts", label: "Security Alerts", icon: ShieldAlert },
  { to: "/investigations", label: "Investigations", icon: Workflow },
  { to: "/agents", label: "AI Agents", icon: Sparkles },
  { to: "/threat-intelligence", label: "Threat Intelligence", icon: Target },
  { to: "/events", label: "Event Explorer", icon: Network },
  { to: "/validation", label: "Detection Validation Lab", icon: FlaskConical },
  { to: "/advanced", label: "Advanced SOC Workbench", icon: BrainCircuit },
];
export function Shell() {
  const auth = useAuth();
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();
  const health = useApi(api.health, []);
  const mode = useApi(api.runtimeMode, []);
  const [search, setSearch] = useState("");
  const title = items.find((item) => item.to === location.pathname)?.label ?? (location.pathname.startsWith("/investigation") ? "Investigation workspace" : "Settings");
  return <div className={`app-shell ${collapsed ? "sidebar-collapsed" : ""}`}>
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark">S</div><div className="brand-copy"><strong>SHERLOCK</strong><span>SOC INTELLIGENCE</span></div><button className="icon-btn collapse-btn" onClick={() => setCollapsed(!collapsed)} aria-label="Toggle sidebar">{collapsed ? <ChevronRight size={17} /> : <ChevronLeft size={17} />}</button></div>
      <nav className="nav-list">{items.map(({ to, label, icon: Icon }) => <NavLink key={to} to={to} className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}><Icon size={18} /><span>{label}</span></NavLink>)}</nav>
      <div className="sidebar-bottom"><NavLink to="/settings" className="nav-item"><Settings size={18} /><span>Settings</span></NavLink>{auth.user ? <button className="nav-item" onClick={() => void auth.logout()}><CircleUserRound size={18} /><span>Sign out</span></button> : <RouterNavLink to="/login" className="nav-item"><CircleUserRound size={18} /><span>Analyst sign in</span></RouterNavLink>}<div className="system-card"><div className="live-dot" /><div><strong>System nominal</strong><span>Backend connected</span></div></div></div>
    </aside>
    <main className="main-content"><header className="topbar"><div><div className="breadcrumb">SHERLOCK <span>/</span> Workspace</div><h1>{title}</h1></div><div className="top-actions"><label className="global-search"><Search size={16} /><input value={search} onChange={(event) => setSearch(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter" && search.trim()) navigate(`/alerts?query=${encodeURIComponent(search.trim())}`); }} placeholder="Search alerts" /><kbd>↵</kbd></label><div className={`mode-indicator mode-${mode.data?.mode ?? "unknown"}`}>{mode.data?.label ?? "Mode unavailable"}</div><div className={`connection ${health.error ? "offline" : ""}`}><span className="live-dot" /> {health.loading ? "Checking" : health.error ? "Offline" : "Connected"}</div><div className="notification" title="Notifications are not configured"><Bell size={18} /><i /></div><div className="avatar" title="Authentication is not configured"><CircleUserRound size={19} /></div></div></header><div className="page-content"><Outlet /></div></main>
  </div>
}
