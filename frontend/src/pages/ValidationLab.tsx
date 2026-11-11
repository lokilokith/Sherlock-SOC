import { useState } from "react";
import { api } from "../services/api";
import { useApi } from "../hooks/useApi";
import { EmptyState, ErrorState, LoadingSkeleton, SectionTitle, StatusBadge } from "../components/ui";
import type { ValidationCaseResult, ValidationRun } from "../types/api";

function metric(value: number | null) { return value == null ? "N/A" : `${Math.round(value * 100)}%`; }

export function ValidationLab() {
  const rules = useApi(api.validationRules);
  const datasets = useApi(api.validationDatasets);
  const history = useApi(api.validationRuns);
  const [run, setRun] = useState<ValidationRun | null>(null);
  const [selected, setSelected] = useState<ValidationCaseResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState("");
  async function validate() {
    setBusy(true); setError("");
    try { const result = await api.validationRun(); setRun(result); setSelected(result.cases[0] ?? null); await history.reload(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Validation failed."); }
    finally { setBusy(false); }
  }
  async function exportReport() {
    if (!active) return;
    setExporting(true); setError("");
    try {
      const blob = await api.downloadValidationReport(active.run_id);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url; link.download = `${active.run_id}.md`; link.click();
      URL.revokeObjectURL(url);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Report export failed."); }
    finally { setExporting(false); }
  }
  const active = run;
  return <><div className="page-heading"><div><span className="eyebrow violet">DETECTION ENGINEERING</span><h2>Detection Validation Lab</h2><p>Evaluate deterministic rules against versioned synthetic telemetry, not real-world accuracy.</p></div><button className="primary-btn" disabled={busy} onClick={() => void validate()}>{busy ? "Validating..." : "Run validation"}</button></div>
    {error && <ErrorState message={error} />}
    <section className="panel"><SectionTitle title="Validation scope" eyebrow="CONTROLLED DATASET" /><div className="validation-scope"><div><strong>{rules.data?.[0]?.rule_id ?? "SOC-001"} · {rules.data?.[0]?.name ?? "Loading rule..."}</strong><span>Rule version {rules.data?.[0]?.version ?? "—"}</span></div><div><strong>{datasets.data?.[0]?.version ?? "—"}</strong><span>{datasets.data?.[0]?.description ?? "Loading dataset..."}</span></div></div></section>
    {!active ? <EmptyState title="No validation run selected" message="Run the approved synthetic dataset to calculate confusion-matrix metrics." /> : <><div className="validation-actions"><button className="text-btn" disabled={exporting} onClick={() => void exportReport()}>{exporting ? "Exporting..." : "Export Markdown report"}</button></div><section className="stat-grid validation-metrics">{[["Precision", active.metrics.precision], ["Recall", active.metrics.recall], ["F1", active.metrics.f1], ["Specificity", active.metrics.specificity], ["Accuracy", active.metrics.accuracy]].map(([label, value]) => <div className="stat-card" key={label as string}><div className="stat-copy"><span>{label as string}</span><strong>{metric(value as number | null)}</strong><small>Dataset metric only</small></div></div>)}</section><section className="panel"><SectionTitle title="Confusion matrix" eyebrow="CLASSIFICATION COUNTS" /><div className="confusion-grid">{(["tp", "fp", "fn", "tn"] as const).map((key) => <div className={`confusion-cell ${key}`} key={key}><span>{key.toUpperCase()}</span><strong>{active.metrics[key]}</strong><small>{key === "tp" ? "Malicious detected" : key === "fp" ? "Benign detected" : key === "fn" ? "Malicious missed" : "Benign ignored"}</small></div>)}</div></section><section className="panel"><SectionTitle title="Test results" eyebrow={`${active.cases.length} CASES EVALUATED`} /><div className="table-scroll"><table><thead><tr><th>Test ID</th><th>Scenario</th><th>Expected</th><th>Actual</th><th>Class</th><th>Conditions</th><th>Missing telemetry</th></tr></thead><tbody>{active.cases.map((item) => <tr className="clickable" key={item.case_id} onClick={() => setSelected(item)}><td className="mono">{item.case_id}</td><td>{item.scenario}</td><td>{item.ground_truth}</td><td>{item.detected ? "Detected" : "Ignored"}</td><td><StatusBadge value={item.classification} /></td><td>{item.matched_conditions.join(", ") || "None"}</td><td>{item.missing_fields.join(", ") || "None"}</td></tr>)}</tbody></table></div></section>{selected && <section className="panel"><SectionTitle title={`Case ${selected.case_id}`} eyebrow="EVALUATION DETAIL" /><div className="validation-detail"><div><strong>{selected.scenario}</strong><p>{selected.description}</p><p>{selected.actual_behavior}; classification <b>{selected.classification}</b>.</p></div><pre>{JSON.stringify(selected.event_fields, null, 2)}</pre></div></section>}</>}
    <section className="panel"><SectionTitle title="Validation history" eyebrow="PERSISTED RUNS" />{history.loading ? <LoadingSkeleton rows={3} /> : history.data?.length ? <div className="table-scroll"><table><thead><tr><th>Run</th><th>Executed</th><th>Rule</th><th>Dataset</th><th>F1</th></tr></thead><tbody>{history.data.map((item) => <tr className="clickable" key={item.run_id} onClick={() => { setRun(item); setSelected(item.cases[0] ?? null); }}><td className="mono">{item.run_id}</td><td>{new Date(item.executed_at).toLocaleString()}</td><td>{item.rule.rule_id}</td><td>{item.dataset.version}</td><td>{metric(item.metrics.f1)}</td></tr>)}</tbody></table></div> : <EmptyState title="No saved runs" message="Completed analyst validation runs will appear here." />}</section>
  </>
}
