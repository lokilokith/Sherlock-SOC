export type Severity = "critical" | "high" | "medium" | "low" | string;
export type InvestigationStatus = "completed" | "partial" | "failed";
export type AgentState = "pending" | "running" | "completed" | "failed" | "skipped";
export type OperatingMode = "demo" | "live" | "unknown";
export interface RuntimeMode { mode: "demo" | "live"; label: string; provider: string }

export interface EvidenceReference { event_id: string; fields: string[] }
export interface Alert {
  alert_id: string; title: string; severity: Severity; event_ids: string[];
  description?: string | null; rule_id: string; rule_name: string;
  timestamp?: string | null; host_id?: string | null; source_event_ids: string[];
  matched_indicators: string[]; evidence_references: EvidenceReference[];
  status: string; priority: string; owner?: string | null; assigned_at?: string | null;
  occurrence_count: number; acknowledgment_status: string; age_hours: number;
}
export interface SecurityEvent {
  event_id: string; source: string; event_type: string; timestamp: string;
  host_id?: string | null; user_id?: string | null; process_id?: number | null;
  parent_process_id?: number | null; process_name?: string | null;
  command_line?: string | null; source_ip?: string | null;
  destination_ip?: string | null; domain?: string | null; file_hash?: string | null;
  raw_payload: Record<string, unknown>;
}
export interface TriageResult {
  alert_id: string; investigation_priority: string; explanation: string;
  missing_information: string[]; evidence_refs: string[];
}
export interface ForensicTimelineEntry { timestamp: string; event_id: string; summary: string; evidence_fields: string[] }
export interface ForensicFinding { description: string; evidence_refs: EvidenceReference[] }
export interface ForensicAnalysis {
  alert_id: string; investigation_summary: string; timeline: ForensicTimelineEntry[];
  process_relationships: { parent_event_id: string; child_event_id: string; relationship: string; evidence_fields: string[] }[];
  observed_behaviors: ForensicFinding[]; hypotheses: ForensicFinding[];
  missing_evidence: string[]; confidence: number; confidence_explanation: string;
  evidence_references: EvidenceReference[]; recommended_next_steps: string[];
}
export interface ThreatIndicator {
  indicator_type: string; normalized_value: string; original_value: string;
  source_event_ids: string[]; source_fields: string[]; provider_name: string;
  verdict: "malicious" | "suspicious" | "benign" | "unknown";
  analysis_stats?: Record<string, number>;
  reputation_score?: number | null; confidence?: number | null; evidence_summary: string;
  source_reference?: string | null; lookup_timestamp: string;
  lookup_status: "available" | "unavailable" | "unknown";
  cached?: boolean;
}
export interface ThreatIntelligenceResult {
  alert_id: string; investigation_summary: string; indicators: ThreatIndicator[];
  missing_information: string[]; recommended_next_steps: string[];
  evidence_references: EvidenceReference[];
}
export interface ThreatIntelProviderStatus {
  id: string; name: string; configured: boolean; configuration_status: string;
  connectivity: "available" | "not-tested" | "unavailable"; supported: string;
  last_successful_lookup: string | null;
}
export interface ThreatIntelOverview {
  configured: number; available: number; unavailable: number; persisted_lookups: number;
  malicious_findings: number; indicators_enriched: number;
}
export interface ThreatIntelConsoleRecord extends ThreatIndicator {
  historical_demo: boolean; associated_alert_id: string | null;
}
export interface AgentExecutionStatus { status: AgentState; error_category?: string | null; error?: string | null }
export interface Finding {
  description: string; source: string;
  classification: "observed_fact" | "hypothesis" | "reputation" | "unknown";
  evidence_references: EvidenceReference[];
}
export interface InvestigationReport {
  investigation_id: string; alert_id: string; investigation_status: InvestigationStatus;
  operating_mode: OperatingMode;
  created_at: string; alert_summary: Alert; triage_analysis?: TriageResult | null;
  forensic_analysis?: ForensicAnalysis | null;
  threat_intelligence_analysis?: ThreatIntelligenceResult | null;
  consolidated_findings: Finding[]; observed_facts: Finding[]; hypotheses: Finding[];
  conflicting_findings: Finding[]; missing_evidence: string[];
  agent_execution_status: Record<string, AgentExecutionStatus>;
  overall_confidence: number; overall_confidence_explanation: string; overall_confidence_label: string;
  detection_confidence?: number | null; detection_confidence_explanation: string;
  evidence_completeness?: number | null; evidence_completeness_explanation: string;
  threat_assessment_confidence?: number | null; threat_assessment_confidence_explanation: string;
  recommended_next_steps: string[];
  evidence_references: EvidenceReference[];
  analyst_assessment?: { conclusion: string; status: string; uncertainty: string; next_actions: string[]; assessor: string; updated_at: string | null };
}
export type ValidationRule = { rule_id: string; name: string; version: string };
export type ValidationDataset = { dataset_id: string; version: string; description: string; case_count: number };
export type ValidationCaseResult = { case_id: string; scenario: string; description: string; ground_truth: "malicious" | "benign"; detected: boolean; expected_behavior: string; actual_behavior: string; matched_conditions: string[]; failed_conditions: string[]; missing_fields: string[]; observability: "available" | "missing" | "not_applicable"; classification: "TP" | "FP" | "FN" | "TN"; event_fields: Record<string, unknown> };
export type ValidationMetrics = { tp: number; fp: number; fn: number; tn: number; precision: number | null; recall: number | null; f1: number | null; specificity: number | null; accuracy: number | null };
export type ValidationRun = { run_id: string; rule: ValidationRule; dataset: ValidationDataset; rule_hash: string; dataset_hash: string; executed_at: string; metrics: ValidationMetrics; cases: ValidationCaseResult[] };
export type InvestigationSummary = { total: number; completed: number; partial: number; failed: number; running: number };
export interface InvestigationListResponse { items: InvestigationReport[]; total: number; limit: number; offset: number }
export interface MitreTechnique {
  id: string;
  stix_id?: string;
  name: string;
  description: string;
  tactics: string[];
  platforms: string[];
  data_sources: string[];
  deprecated?: boolean;
}
export interface MitreMatrix {
  tactics: Array<{ name: string; short_name: string; techniques: MitreTechnique[] }>;
}
