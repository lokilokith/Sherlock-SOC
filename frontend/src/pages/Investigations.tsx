import { ArrowUpRight, Search } from "lucide-react";
import React from "react";
import { useNavigate } from "react-router-dom";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import { EmptyState, ErrorState, LoadingSkeleton, SectionTitle, StatusBadge } from "../components/ui";
export function Investigations() { const { data, loading, error } = useApi(() => api.investigationsList(), []); const [query, setQuery] = React.useState(""); const navigate = useNavigate();
  const reports = data?.items ?? [];
  const filtered = reports.filter((r) => `${r.investigation_id} ${r.alert_id}`.toLowerCase().includes(query.toLowerCase()));
  return <><div className="page-heading"><div><span className="eyebrow violet">CASE MANAGEMENT</span><h2>Investigations</h2><p>Persisted coordinated investigations and their specialist results.</p></div></div><section className="panel"><SectionTitle title="Investigation history" eyebrow="PERSISTED WORKSPACE" /><label className="search-field wide-search"><Search size={17} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search investigation or alert ID..." /></label>{loading ? <LoadingSkeleton rows={5} /> : error ? <ErrorState message={error} /> : filtered.length ? <div className="table-scroll"><table><thead><tr><th>Investigation</th><th>Alert</th><th>Status</th><th>Created</th><th /></tr></thead><tbody>{filtered.map((report) => <tr className="clickable" key={report.investigation_id} onClick={() => navigate(`/investigations/${encodeURIComponent(report.investigation_id)}`)}><td className="mono">{report.investigation_id}</td><td>{report.alert_id}</td><td><StatusBadge value={report.investigation_status} /></td><td className="muted">{new Date(report.created_at).toLocaleString()}</td><td><ArrowUpRight size={16} /></td></tr>)}</tbody></table></div> : <EmptyState title="No investigations yet" message="Start an investigation from a security alert." />}</section></> }
