import { useEffect, useState } from "react";
import { api } from "../services/api";
import { EmptyState, ErrorState, LoadingSkeleton, SectionTitle } from "../components/ui";

type MitreTechnique = {
  id: string;
  name: string;
  description: string;
  tactics: string[];
  platforms: string[];
  data_sources: string[];
};
type MitreMatrix = {
  tactics: Array<{ name: string; short_name: string; techniques: MitreTechnique[] }>;
};

export function AdvancedSOC() {
  const [overview, setOverview] = useState<Record<string, string | number | boolean> | null>(null);
  const [matrix, setMatrix] = useState<MitreMatrix | null>(null);
  const [technique, setTechnique] = useState<MitreTechnique | null>(null);
  const [coverage, setCoverage] = useState<Record<string, unknown> | null>(null);
  const [rules, setRules] = useState<Array<{ rule_id: string; name: string; description: string; severity: string; version: string; mitre_techniques: string[]; rationale: string }>>([]);
  const [query, setQuery] = useState("");
  const [hunt, setHunt] = useState<{ total: number; matches: Array<Record<string, string | null>> } | null>(null);
  const [ioc, setIoc] = useState("");
  const [iocResult, setIocResult] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([api.mitreOverview(), api.mitreMatrix(), api.detectionCoverage(), api.detectionRules()])
      .then(([overviewResult, matrixResult, coverageResult, ruleResult]) => {
        setOverview(overviewResult);
        setMatrix(matrixResult);
        setCoverage(coverageResult);
        setRules(ruleResult);
      })
      .catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Failed to load SOC capabilities."))
      .finally(() => setLoading(false));
  }, []);

  async function selectTechnique(id: string) {
    try {
      setTechnique(await api.mitreTechnique(id));
      setError("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Failed to load technique.");
    }
  }

  async function runHunt() {
    try {
      setHunt(await api.huntingSearch({ indicator: query }));
      setError("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Threat hunt failed.");
    }
  }

  async function exploreIoc() {
    if (!ioc.trim()) return;
    try {
      setIocResult(await api.iocExplorer(ioc.trim()));
      setError("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "IOC exploration failed.");
    }
  }

  if (loading) return <LoadingSkeleton rows={10} />;
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow violet">ADVANCED ANALYSIS</span>
          <h2>MITRE ATT&amp;CK and SOC Workbench</h2>
          <p>Local Enterprise ATT&amp;CK intelligence, detection coverage, threat hunting, and IOC relationships.</p>
        </div>
      </div>
      {error && <ErrorState message={error} />}
      <section className="stat-grid">
        {overview && Object.entries(overview)
          .filter(([key]) => ["tactic_count", "technique_count", "relationship_count"].includes(key))
          .map(([key, value]) => (
            <div className="stat-card" key={key}>
              <div className="stat-copy"><span>{key.replace(/_/g, " ")}</span><strong>{String(value)}</strong></div>
            </div>
          ))}
        <div className="stat-card">
          <div className="stat-copy"><span>Mapped detection rules</span><strong>{String((coverage?.covered_rules ?? 0))}</strong></div>
        </div>
      </section>

      <section className="panel">
        <SectionTitle title="Interactive Enterprise ATT&amp;CK matrix" eyebrow={`${matrix?.tactics.length ?? 0} TACTICS`} />
        <div className="attack-matrix">
          {matrix?.tactics.map((tactic) => (
            <div className="attack-column" key={tactic.short_name}>
              <h3>{tactic.name}</h3>
              {tactic.techniques.map((item) => (
                <button className="attack-technique" key={item.id} onClick={() => void selectTechnique(item.id)}>
                  <strong>{item.id}</strong><span>{item.name}</span>
                </button>
              ))}
            </div>
          ))}
        </div>
      </section>

      <section className="panel">
        <SectionTitle title="Detection engineering rules" eyebrow={`${rules.length} PERSISTED DEFINITIONS`} />
        <div className="table-scroll">
          <table><thead><tr><th>Rule</th><th>Severity</th><th>Version</th><th>ATT&amp;CK</th><th>Detection rationale</th></tr></thead><tbody>
            {rules.map((rule) => <tr key={rule.rule_id}><td><strong>{rule.rule_id}</strong><br /><small>{rule.name}</small></td><td>{rule.severity}</td><td>{rule.version}</td><td>{rule.mitre_techniques.join(", ")}</td><td>{rule.rationale}</td></tr>)}
          </tbody></table>
        </div>
      </section>

      {technique && (
        <section className="panel">
          <SectionTitle title={`${technique.id} · ${technique.name}`} eyebrow="TECHNIQUE DETAIL" />
          <p>{technique.description}</p>
          <div className="detail-grid">
            <div><span className="eyebrow">PLATFORMS</span><p>{technique.platforms.join(", ") || "Not specified"}</p></div>
            <div><span className="eyebrow">TACTICS</span><p>{technique.tactics.join(", ") || "None"}</p></div>
            <div><span className="eyebrow">DATA SOURCES</span><p>{technique.data_sources.join(", ") || "Not specified"}</p></div>
          </div>
        </section>
      )}

      <div className="two-column">
        <section className="panel">
          <SectionTitle title="Threat hunting workbench" eyebrow="PERSISTED TELEMETRY" />
          <div className="inline-form">
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="IOC, domain, IP, hash, or process text" />
            <button className="primary-btn" onClick={() => void runHunt()}>Search telemetry</button>
          </div>
          {hunt ? <div className="table-scroll"><p><strong>{hunt.total}</strong> matching events</p>{hunt.matches.map((match) => (
            <div className="finding" key={String(match.event_id)}>
              <p>{String(match.process_name ?? "Unknown process")}</p>
              <small>{String(match.event_id)} · {String(match.host_id ?? "Unknown host")} · {String(match.command_line ?? "")}</small>
            </div>
          ))}</div> : <EmptyState title="No hunt run" message="Search the preserved event store for indicators or process terms." />}
        </section>
        <section className="panel">
          <SectionTitle title="IOC relationship explorer" eyebrow="REPUTATION & ASSOCIATIONS" />
          <div className="inline-form">
            <input value={ioc} onChange={(event) => setIoc(event.target.value)} placeholder="Indicator value" />
            <button className="primary-btn" onClick={() => void exploreIoc()}>Explore IOC</button>
          </div>
          {iocResult ? <pre>{JSON.stringify(iocResult, null, 2)}</pre> : <EmptyState title="No IOC selected" message="Explore persistence-backed providers, alerts, and events." />}
        </section>
      </div>
    </>
  );
}
