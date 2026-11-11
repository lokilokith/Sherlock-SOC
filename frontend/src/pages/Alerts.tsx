import { Filter, Play, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../services/api";
import { useApi } from "../hooks/useApi";
import { EmptyState, ErrorState, LoadingSkeleton, SeverityBadge, StatusBadge } from "../components/ui";

export function Alerts() {
  const { data, loading, error } = useApi(api.alerts);
  const [params] = useSearchParams();
  const [query, setQuery] = useState(params.get("query") ?? "");
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("all");
  const [owner, setOwner] = useState("all");
  const navigate = useNavigate();
  const alerts = useMemo(() => (data ?? [])
    .filter((a) => `${a.alert_id} ${a.rule_name} ${a.host_id ?? ""}`.toLowerCase().includes(query.toLowerCase()))
    .filter((a) => severity === "all" || a.severity.toLowerCase() === severity)
    .filter((a) => status === "all" || a.status === status)
    .filter((a) => owner === "all" || (owner === "unassigned" ? !a.owner : a.owner === owner)),
    [data, query, severity, status, owner]);
  const owners = useMemo(() => Array.from(new Set((data ?? []).map((a) => a.owner).filter((value): value is string => Boolean(value)))), [data]);
  return <><div className="page-heading"><div><span className="eyebrow">DETECTION QUEUE</span><h2>Security alerts</h2><p>Investigate and prioritize evidence-backed detections.</p></div><div className="heading-meta"><span className="count-pill">{alerts.length} alerts</span></div></div><section className="panel"><div className="toolbar"><label className="search-field"><Search size={17} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search alerts, rules or hosts..." /></label><label className="select-field"><Filter size={15} /><select value={severity} onChange={(e) => setSeverity(e.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label><label className="select-field"><select value={status} onChange={(e) => setStatus(e.target.value)}><option value="all">All statuses</option>{["New", "Acknowledged", "Investigating", "Escalated", "Resolved", "Closed", "False Positive"].map((value) => <option key={value}>{value}</option>)}</select></label><label className="select-field"><select value={owner} onChange={(e) => setOwner(e.target.value)}><option value="all">All owners</option><option value="unassigned">Unassigned</option>{owners.map((value) => <option key={value}>{value}</option>)}</select></label></div>{loading ? <LoadingSkeleton rows={7} /> : error ? <ErrorState message={error} /> : alerts.length === 0 ? <EmptyState title="No matching alerts" message="Try a different filter or import more telemetry." /> : <div className="table-scroll"><table><thead><tr><th>Alert ID</th><th>Detection rule</th><th>Host</th><th>Severity</th><th>Priority</th><th>Status</th><th>Owner</th><th>Evidence</th><th>Detected</th><th /></tr></thead><tbody>{alerts.map((alert) => <tr key={alert.alert_id} className="clickable" onClick={() => navigate(`/alerts/${encodeURIComponent(alert.alert_id)}`)}><td className="mono">{alert.alert_id}</td><td><strong>{alert.rule_name || alert.rule_id}</strong><small className="table-sub">{alert.title}</small></td><td>{alert.host_id || "—"}</td><td><SeverityBadge value={alert.severity} /></td><td>{alert.priority}</td><td><StatusBadge value={alert.status} /></td><td>{alert.owner || "Unassigned"}</td><td>{alert.evidence_references.length} events{alert.occurrence_count > 1 ? ` / ${alert.occurrence_count} occurrences` : ""}</td><td className="muted">{alert.timestamp ? new Date(alert.timestamp).toLocaleString() : "—"}</td><td><button className="icon-btn" title="Open alert"><Play size={15} /></button></td></tr>)}</tbody></table></div>}</section></>;
}
