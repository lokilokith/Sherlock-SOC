import { ExternalLink, RefreshCw, Search, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api } from "../services/api";
import { SectionTitle, StatusBadge } from "../components/ui";
import type { ThreatIndicator, ThreatIntelOverview, ThreatIntelProviderStatus } from "../types/api";

const providerNames: Record<string, string> = {
  virustotal: "VirusTotal",
  abuseipdb: "AbuseIPDB",
  alienvault_otx: "AlienVault OTX",
  greynoise: "GreyNoise Community",
  urlhaus: "URLhaus",
};

const providerIcon: Record<string, string> = {
  virustotal: "VT",
  abuseipdb: "AIP",
  alienvault_otx: "OTX",
  greynoise: "GN",
  urlhaus: "UH",
};

function sourceLink(reference?: string | null) {
  return reference?.replace("/gui/files/", "/gui/file/") ?? null;
}

function providerEvidence(ioc: ThreatIndicator) {
  const stats = ioc.analysis_stats ?? {};
  const values = Object.entries(stats).map(([key, value]) => `${key.replace(/_/g, " ")} ${value}`);
  return [ioc.evidence_summary, ...values].filter(Boolean).join(" · ");
}

export function ThreatIntel() {
  const [status, setStatus] = useState<{ providers: ThreatIntelProviderStatus[]; overview: ThreatIntelOverview }>();
  const [persisted, setPersisted] = useState<ThreatIndicator[]>([]);
  const [ioc, setIoc] = useState("");
  const [type, setType] = useState("auto");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [providerFilter, setProviderFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState("all");
  const [verdictFilter, setVerdictFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [selected, setSelected] = useState<string>("");
  const [comparison, setComparison] = useState<ThreatIndicator[]>([]);

  const load = async () => {
    const [health, records] = await Promise.all([
      api.threatIntelStatus(),
      api.threatIntelConsole(),
    ]);
    setStatus(health);
    setPersisted(records.records);
  };

  useEffect(() => {
    void load().catch((reason) => setError(reason instanceof Error ? reason.message : "Unable to load threat intelligence."));
  }, []);

  const enrichIoc = async () => {
    setError("");
    if (!ioc.trim()) {
      setError("Enter an IOC to investigate.");
      return;
    }
    setLoading(true);
    try {
      const results = await api.manualThreatIntel(ioc.trim(), type);
      setComparison(results);
      setSelected(ioc.trim());
      await load();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The enrichment request failed.");
    } finally {
      setLoading(false);
    }
  };

  const filtered = useMemo(() => persisted.filter((record) => {
    const historical = "historical_demo" in record && Boolean(record.historical_demo);
    const provenance = historical ? "historical" : record.cached ? "cached" : "live";
    return (providerFilter === "all" || record.provider_name === providerFilter) &&
      (typeFilter === "all" || record.indicator_type === typeFilter) &&
      (verdictFilter === "all" || record.verdict === verdictFilter) &&
      (sourceFilter === "all" || sourceFilter === provenance) &&
      `${record.normalized_value} ${record.evidence_summary}`.toLowerCase().includes(search.toLowerCase());
  }), [persisted, providerFilter, typeFilter, verdictFilter, sourceFilter, search]);

  const currentDetails = persisted.filter((record) =>
    record.normalized_value.toLowerCase() === selected.toLowerCase());

  const overview = status?.overview;

  return (
    <div className="ti-console">
      <div className="page-heading">
        <div><span className="eyebrow cyan">THREAT OPERATIONS</span><h2>Threat intelligence</h2><p>Multi-provider reputation, enrichment and persistent intelligence evidence.</p></div>
        <button className="secondary-btn" onClick={() => void load()}><RefreshCw size={15} /> Refresh</button>
      </div>

      <section>
        <SectionTitle title="Threat Intelligence Overview" eyebrow="LIVE DATA" />
        <div className="ti-stat-grid">
          {[
            ["Configured providers", overview?.configured ?? 0],
            ["Available providers", overview?.available ?? 0],
            ["Unavailable providers", overview?.unavailable ?? 0],
            ["Persisted lookups", overview?.persisted_lookups ?? 0],
            ["Malicious findings", overview?.malicious_findings ?? 0],
            ["Indicators enriched", overview?.indicators_enriched ?? 0],
          ].map(([label, value]) => <div className="ti-stat" key={String(label)}><span>{label}</span><strong>{value}</strong></div>)}
        </div>
      </section>

      <section>
        <SectionTitle title="Provider Health" eyebrow="CONFIGURATION & CONNECTIVITY" />
        <div className="provider-health-grid">
          {(status?.providers ?? []).map((provider) => (
            <article className="provider-health-card" key={provider.id}>
              <div className="provider-health-head">
                <div className={`provider-monogram provider-${provider.id}`}>{providerIcon[provider.id]}</div>
                <div><strong>{provider.name}</strong><span>{provider.supported}</span></div>
                <StatusBadge value={provider.connectivity === "available" ? "online" : provider.configuration_status} />
              </div>
              <dl>
                <div><dt>Configuration</dt><dd>{provider.configuration_status}</dd></div>
                <div><dt>Connectivity</dt><dd>{provider.connectivity === "not-tested" ? "Not tested" : provider.connectivity}</dd></div>
                <div><dt>Last success</dt><dd>{provider.last_successful_lookup ? new Date(provider.last_successful_lookup).toLocaleString() : "No successful lookup"}</dd></div>
              </dl>
            </article>
          ))}
        </div>
      </section>

      <section className="panel ti-investigation">
        <SectionTitle title="Manual IOC Investigation" eyebrow="MULTI-PROVIDER LOOKUP" />
        <form onSubmit={(event) => { event.preventDefault(); void enrichIoc(); }}>
          <div className="ti-investigation-controls">
            <label className="ti-ioc-field"><span>IOC value</span><div><input value={ioc} onChange={(event) => setIoc(event.target.value)} placeholder="IP, domain, URL, MD5, SHA1 or SHA256" /><button type="button" className="icon-btn" title="Clear IOC" disabled={!ioc} onClick={() => { setIoc(""); setError(""); }}><Trash2 size={16} /></button></div></label>
            <label><span>Indicator type</span><select value={type} onChange={(event) => setType(event.target.value)}><option value="auto">Auto-detect</option><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option><option value="domain">Domain</option><option value="url">URL</option><option value="md5">MD5</option><option value="sha1">SHA1</option><option value="sha256">SHA256</option></select></label>
            <button className="primary-btn" disabled={loading || !ioc.trim()}>{loading ? "Investigating..." : "Enrich IOC"}</button>
          </div>
        </form>
        {error && <div className="notice error">{error}</div>}
        {loading && <div className="ti-progress"><span /> Looking up applicable providers...</div>}
        {!loading && comparison.length > 0 && <div className="ti-completion">Completed with {comparison.length} provider {comparison.length === 1 ? "result" : "results"}; unavailable providers remain explicitly reported.</div>}
      </section>

      <section>
        <SectionTitle title="Multi-Provider Investigation Results" eyebrow="INDIVIDUAL PROVIDER EVIDENCE" />
        {comparison.length ? <div className="ti-provider-results">
          {comparison.map((lookup) => (
            <details className="ti-result-card" open key={`${lookup.provider_name}-${lookup.normalized_value}`}>
              <summary><span className={`provider-monogram provider-${lookup.provider_name}`}>{providerIcon[lookup.provider_name]}</span><strong>{providerNames[lookup.provider_name] ?? lookup.provider_name}</strong><StatusBadge value={lookup.verdict} /><StatusBadge value={lookup.lookup_status} /><span>{lookup.cached ? "Cached" : "Live"}</span></summary>
              <div className="ti-result-body">
                <p>{lookup.evidence_summary}</p>
                {Object.entries(lookup.analysis_stats ?? {}).length > 0 && <div className="evidence-grid">{Object.entries(lookup.analysis_stats ?? {}).map(([key, value]) => <div key={key}><span>{key.replace(/_/g, " ")}</span><strong>{value}</strong></div>)}</div>}
                <div className="muted">Last checked: {new Date(lookup.lookup_timestamp).toLocaleString()}</div>
                {sourceLink(lookup.source_reference) && <a className="tag" href={sourceLink(lookup.source_reference)!} target="_blank" rel="noreferrer"><ExternalLink size={13} /> Provider source</a>}
              </div>
            </details>
          ))}
        </div> : <div className="empty-panel">Submit an IOC to view provider-specific results.</div>}
      </section>

      <section className="panel">
        <SectionTitle title="Provider Comparison" eyebrow={comparison.length ? "CURRENT INVESTIGATION" : "AWAITING IOC"} />
        {comparison.length ? <div className="table-scroll"><table className="ti-table"><thead><tr><th>Provider</th><th>Result</th><th>Verdict</th><th>Evidence</th><th>Lookup status</th><th>Last checked</th></tr></thead><tbody>{comparison.map((lookup) => <tr key={lookup.provider_name}><td>{providerNames[lookup.provider_name] ?? lookup.provider_name}</td><td>{lookup.lookup_status === "available" ? (lookup.verdict === "unknown" ? "No result / unknown" : "Result available") : "Unavailable"}</td><td><StatusBadge value={lookup.verdict} /></td><td>{providerEvidence(lookup)}</td><td>{lookup.lookup_status}</td><td>{new Date(lookup.lookup_timestamp).toLocaleString()}</td></tr>)}</tbody></table></div> : <div className="empty-panel">Provider disagreement and evidence will appear here.</div>}
      </section>

      <section className="panel">
        <SectionTitle title="Persisted IOC Intelligence" eyebrow="SEARCHABLE LOOKUP HISTORY" />
        <div className="ti-filters">
          <label><Search size={16} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search IOC or evidence" /></label>
          <select value={providerFilter} onChange={(event) => setProviderFilter(event.target.value)}><option value="all">All providers</option>{Object.keys(providerNames).map((provider) => <option value={provider} key={provider}>{providerNames[provider]}</option>)}</select>
          <select value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)}><option value="all">All types</option>{["ipv4","ipv6","domain","url","md5","sha1","sha256"].map((value) => <option value={value} key={value}>{value.toUpperCase()}</option>)}</select>
          <select value={verdictFilter} onChange={(event) => setVerdictFilter(event.target.value)}><option value="all">All verdicts</option>{["malicious","suspicious","benign","unknown"].map((value) => <option value={value} key={value}>{value}</option>)}</select>
          <select value={sourceFilter} onChange={(event) => setSourceFilter(event.target.value)}><option value="all">All sources</option><option value="live">Live</option><option value="cached">Cached</option><option value="historical">Historical demo</option></select>
        </div>
        <div className="table-scroll"><table className="ti-table"><thead><tr><th>Indicator</th><th>Type</th><th>Provider</th><th>Verdict</th><th>Status</th><th>Source</th><th>Evidence</th><th>Timestamp</th><th>Cache</th></tr></thead><tbody>{filtered.map((record, index) => {
          const historical = "historical_demo" in record && Boolean(record.historical_demo);
          return <tr key={`${record.provider_name}-${record.normalized_value}-${index}`} className="ti-record-row" onClick={() => setSelected(record.normalized_value)}>
            <td className="mono">{record.normalized_value}</td><td>{record.indicator_type.toUpperCase()}</td><td>{providerNames[record.provider_name] ?? record.provider_name}</td><td><StatusBadge value={record.verdict} /></td><td>{record.lookup_status}</td>
            <td>{historical ? <span className="demo-label">Historical demo</span> : sourceLink(record.source_reference) ? <a href={sourceLink(record.source_reference)!} target="_blank" rel="noreferrer">Source</a> : "—"}</td>
            <td className="ti-evidence">{record.evidence_summary}</td><td>{new Date(record.lookup_timestamp).toLocaleString()}</td><td>{historical ? "Historical" : record.cached ? "Cached" : "Live"}</td>
          </tr>;
        })}</tbody></table></div>
      </section>

      <section className="panel ti-details">
        <SectionTitle title="IOC Investigation Details" eyebrow="SELECTED INDICATOR" />
        {selected && currentDetails.length ? <div>
          <h3 className="mono">{selected}</h3>
          <div className="ti-detail-grid">{currentDetails.map((record, index) => <article key={index}><strong>{providerNames[record.provider_name] ?? record.provider_name}</strong><StatusBadge value={record.verdict} /><p>{record.evidence_summary}</p><div className="muted">Events: {record.source_event_ids.length ? record.source_event_ids.join(", ") : "No associated event"}{("associated_alert_id" in record && record.associated_alert_id) ? ` · Alert: ${record.associated_alert_id}` : ""}</div></article>)}</div>
        </div> : <div className="empty-panel">Select a persisted indicator to inspect provider details and associations.</div>}
      </section>
    </div>
  );
}
