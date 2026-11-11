import {
  ArrowLeft,
  Bot,
  CheckCircle2,
  Clock3,
  FileSearch,
  Globe2,
  ShieldCheck,
} from "lucide-react";
import type React from "react";
import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import {
  AgentStatus,
  EmptyState,
  ErrorState,
  LoadingSkeleton,
  SectionTitle,
  SeverityBadge,
  StatusBadge,
} from "../components/ui";
import type { InvestigationReport, Finding } from "../types/api";
function Findings({
  title,
  items,
  tone,
}: {
  title: string;
  items: Finding[];
  tone: string;
}) {
  return (
    <div className={`finding-group ${tone}`}>
      <h3>
        {title}
        <span>{items.length}</span>
      </h3>
      {items.length ? (
        items.map((item, i) => (
          <div className="finding" key={`${item.description}-${i}`}>
            <p>{item.description}</p>
            <small>
              {item.source} ·{" "}
              {item.evidence_references.map((r) => r.event_id).join(", ") ||
                "No references"}
            </small>
          </div>
        ))
      ) : (
        <span className="muted">No findings recorded.</span>
      )}
    </div>
  );
}
function ScoreCard({
  title,
  value,
  explanation,
  unavailable = "Insufficient evidence",
}: {
  title: string;
  value?: number | null;
  explanation: string;
  unavailable?: string;
}) {
  return (
    <div className="score-card" title={explanation}>
      <span className="eyebrow">{title}</span>
      <strong>
        {value == null ? unavailable : `${Math.round(value * 100)}%`}
      </strong>
      <p>{explanation}</p>
    </div>
  );
}
function AgentPanel({
  name,
  icon: Icon,
  status,
  children,
}: {
  name: string;
  icon: typeof Bot;
  status?: import("../types/api").AgentExecutionStatus;
  children: React.ReactNode;
}) {
  return (
    <section className="panel agent-panel">
      <div className="agent-panel-head">
        <div className="agent-avatar agent-violet">
          <Icon size={19} />
        </div>
        <div>
          <span className="eyebrow">SPECIALIST AGENT</span>
          <h3>{name}</h3>
        </div>
        {status && <AgentStatus status={status} />}
      </div>
      {children}
    </section>
  );
}
function InvestigationIntelligence({ investigationId }: { investigationId: string }) {
  const [storyline, setStoryline] = useState<{ summary: string; events: Array<{ timestamp: string; event_id: string; process: string | null; command_line: string | null }> } | null>(null);
  const [quality, setQuality] = useState<{ confidence: number; label: string; components: Record<string, number | boolean> } | null>(null);
  const [copilot, setCopilot] = useState<{ summary: string; observations: string[]; questions: string[]; recommended_actions: string[] } | null>(null);
  const [assessment, setAssessment] = useState("No analyst assessment recorded.");
  const [assessmentStatus, setAssessmentStatus] = useState("open");
  const [assessmentError, setAssessmentError] = useState("");

  useEffect(() => {
    Promise.all([
      api.investigationStoryline(investigationId),
      api.investigationEvidenceQuality(investigationId),
      api.investigationCopilot(investigationId),
    ]).then(([story, evidence, assistant]) => {
      setStoryline(story);
      setQuality(evidence);
      setCopilot(assistant);
    }).catch(() => undefined);
  }, [investigationId]);

  async function saveAssessment() {
    try {
      await api.saveInvestigationAssessment(investigationId, {
        conclusion: assessment,
        status: assessmentStatus,
        uncertainty: "",
        next_actions: [],
        assessor: "analyst",
      });
      setAssessmentError("");
    } catch (reason) {
      setAssessmentError(reason instanceof Error ? reason.message : "Assessment could not be saved.");
    }
  }

  return (
    <>
    <div className="two-column">
      <section className="panel">
        <SectionTitle title="Attack Storyline Reconstruction" eyebrow="EVIDENCE TIMELINE" />
        {storyline?.events.length ? storyline.events.map((event) => (
          <div className="timeline-item" key={event.event_id}>
            <div className="timeline-dot" />
            <div><strong>{event.process || "Observed event"}</strong><span>{new Date(event.timestamp).toLocaleString()} · <code>{event.event_id}</code></span>{event.command_line && <p>{event.command_line}</p>}</div>
          </div>
        )) : <EmptyState title="No storyline events" message={storyline?.summary || "No evidence-backed timeline has been reconstructed."} />}
      </section>
      <section className="panel">
        <SectionTitle title="Evidence Quality and SOC Copilot" eyebrow="CONFIDENCE & ASSISTANCE" />
        {quality && <div className="notice"><strong>{quality.label} evidence confidence · {Math.round(quality.confidence * 100)}%</strong><p>{quality.components.evidence_references} evidence references; {quality.components.distinct_observed_fields} distinct observed fields.</p></div>}
        {copilot && <>
          <p>{copilot.summary}</p>
          {copilot.observations.map((item) => <div className="finding" key={item}><p>{item}</p></div>)}
          {copilot.recommended_actions.map((item) => <div className="notice" key={item}><p>{item}</p></div>)}
          {copilot.questions.length > 0 && <small>Copilot questions: {copilot.questions.join(" ")}</small>}
        </>}
      </section>
    </div>
    <section className="panel">
      <SectionTitle title="Analyst Assessment" eyebrow="PERSISTED CONCLUSION" />
      {assessmentError && <ErrorState message={assessmentError} />}
      <div className="inline-form">
        <textarea value={assessment} onChange={(event) => setAssessment(event.target.value)} />
        <select value={assessmentStatus} onChange={(event) => setAssessmentStatus(event.target.value)}>
          <option value="open">Open</option>
          <option value="confirmed">Confirmed</option>
          <option value="false_positive">False positive</option>
          <option value="closed">Closed</option>
        </select>
        <button className="primary-btn" onClick={() => void saveAssessment()}>Save assessment</button>
      </div>
    </section>
    </>
  );
}
export function Investigation() {
  const { investigationId = "" } = useParams();
  const { data, loading, error } = useApi(
    () => api.investigation(decodeURIComponent(investigationId)),
    [investigationId],
  );
  const navigate = useNavigate();
  if (loading) return <LoadingSkeleton rows={10} />;
  if (error || !data)
    return <ErrorState message={error || "Investigation not found."} />;
  return (
    <>
      <button className="back-btn" onClick={() => navigate("/investigations")}>
        <ArrowLeft size={15} /> Back to investigations
      </button>
      <div className="investigation-header">
        <div>
          <span className="eyebrow violet">INVESTIGATION WORKSPACE</span>
          <h2>{data.investigation_id}</h2>
          <p className="mono">{data.alert_id}</p>
        </div>
        <div className="investigation-meta">
          <span className={`mode-indicator mode-${data.operating_mode}`}>
            {data.operating_mode === "demo"
              ? "DEMO MODE — Mock providers"
              : data.operating_mode === "live"
                ? "LIVE MODE — VirusTotal / Deterministic fallback"
                : "MODE UNKNOWN"}
          </span>
          <SeverityBadge value={data.alert_summary.severity} />
          <StatusBadge value={data.investigation_status} />
          <span className="muted">
            {new Date(data.created_at).toLocaleString()}
          </span>
        </div>
      </div>
      <section className="score-grid">
        <ScoreCard
          title="Detection Rule Match Strength"
          value={data.detection_confidence}
          explanation={data.detection_confidence_explanation}
        />
        <ScoreCard
          title="Evidence Completeness"
          value={data.evidence_completeness}
          explanation={data.evidence_completeness_explanation}
        />
        <ScoreCard
          title="Threat Assessment"
          value={data.threat_assessment_confidence}
          explanation={data.threat_assessment_confidence_explanation}
        />
        <ScoreCard
          title="Investigation Execution"
          value={null}
          unavailable={data.investigation_status}
          explanation="Execution status is independent from evidence quality and threat assessment."
        />
      </section>
      <div className="report-banner">
        <div className="report-icon">
          <ShieldCheck size={21} />
        </div>
        <div>
          <span className="eyebrow">UNIFIED REPORT</span>
          <h3>{data.alert_summary.title}</h3>
          <p>
            {data.recommended_next_steps[0] ||
              "Evidence-backed specialist analysis is available below."}
          </p>
        </div>
      </div>
      <div className="agent-grid investigation-agents">
        <AgentPanel
          name="Triage Agent"
          icon={Bot}
          status={data.agent_execution_status.triage}
        >
          <div className="agent-result">
            <div className="mini-stat">
              <span>Priority</span>
              <strong>
                {data.triage_analysis?.investigation_priority ?? "Unavailable"}
              </strong>
            </div>
            <p>
              {data.triage_analysis?.explanation ??
                "No triage result was produced."}
            </p>
            {data.triage_analysis?.missing_information.length ? (
              <div className="notice warning">
                Missing: {data.triage_analysis.missing_information.join(", ")}
              </div>
            ) : null}
          </div>
        </AgentPanel>
        <AgentPanel
          name="Forensics Agent"
          icon={FileSearch}
          status={data.agent_execution_status.forensics}
        >
          <div className="agent-result">
            <p>
              {data.forensic_analysis?.investigation_summary ??
                "No forensic result was produced."}
            </p>
            {data.forensic_analysis?.timeline.length ? (
              <div className="timeline">
                {data.forensic_analysis.timeline.map((entry) => (
                  <div
                    className="timeline-item"
                    key={`${entry.event_id}-${entry.timestamp}`}
                  >
                    <div className="timeline-dot" />
                    <div>
                      <strong>{entry.summary}</strong>
                      <span>
                        {new Date(entry.timestamp).toLocaleString()} ·{" "}
                        <code>{entry.event_id}</code>
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState
                title="No timeline"
                message="No chronological entries were returned."
              />
            )}
          </div>
        </AgentPanel>
        <AgentPanel
          name="Threat Intelligence Agent"
          icon={Globe2}
          status={data.agent_execution_status.threat_intelligence}
        >
          <div className="agent-result">
            <p>
              {data.threat_intelligence_analysis?.investigation_summary ??
                "No threat intelligence result was produced."}
            </p>
            {data.threat_intelligence_analysis?.indicators.length ? (
              <div className="ioc-list">
                {data.threat_intelligence_analysis.indicators.map((ioc) => (
                  <div
                    className="ioc-row"
                    key={`${ioc.indicator_type}-${ioc.normalized_value}`}
                  >
                    <span className="ioc-type">{ioc.indicator_type}</span>
                    <strong className="mono">{ioc.normalized_value}</strong>
                    <StatusBadge value={ioc.verdict} />
                    <span className="muted">{ioc.lookup_status}</span>
                    <span className="muted">
                      {ioc.cached ? "cached" : "not cached"} · {ioc.provider_name}
                    </span>
                    <span className="muted">
                      {new Date(ioc.lookup_timestamp).toLocaleString()}
                    </span>
                    {ioc.source_reference ? (
                      <a
                        className="tag"
                        href={ioc.source_reference}
                        target="_blank"
                        rel="noreferrer"
                      >
                        Source reference
                      </a>
                    ) : null}
                    <span className="muted">
                      {Object.entries(ioc.analysis_stats ?? {})
                        .map(([name, count]) => `${name}: ${count}`)
                        .join(" · ")}
                    </span>
                    <span className="muted">
                      Events: {ioc.source_event_ids.join(", ")}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState
                title="No indicators"
                message="No indicators were extracted from evidence."
              />
            )}
          </div>
        </AgentPanel>
      </div>
      <InvestigationIntelligence investigationId={data.investigation_id} />
      <section className="panel">
        <SectionTitle title="Consolidated findings" eyebrow="ANALYST REPORT" />
        <div className="findings-grid">
          <Findings
            title="Confirmed observations"
            items={data.observed_facts}
            tone="fact"
          />
          <Findings
            title="Hypotheses"
            items={data.hypotheses}
            tone="hypothesis"
          />
          <Findings
            title="Conflicting findings"
            items={data.conflicting_findings}
            tone="conflict"
          />
        </div>
        {data.missing_evidence.length ? (
          <div className="notice warning">
            <Clock3 size={16} /> {data.missing_evidence.join(" · ")}
          </div>
        ) : null}
      </section>
      <section className="panel">
        <SectionTitle title="Evidence references" eyebrow="TRACEABILITY" />
        <div className="tag-list">
          {data.evidence_references.map((ref) => (
            <span className="tag" key={`${ref.event_id}-${ref.fields.join()}`}>
              <CheckCircle2 size={13} /> {ref.event_id} ·{" "}
              {ref.fields.join(", ")}
            </span>
          ))}
        </div>
      </section>
    </>
  );
}
