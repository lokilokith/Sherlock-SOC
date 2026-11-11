import type { Alert, ForensicAnalysis, InvestigationListResponse, InvestigationReport, InvestigationSummary, RuntimeMode, SecurityEvent, ThreatIntelligenceResult, TriageResult, ValidationDataset, ValidationRun, ValidationRule } from "../types/api";

const baseUrl = import.meta.env.VITE_API_BASE_URL ?? "";
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, { credentials: "include", ...init, headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) } });
  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try { const body = await response.json(); detail = body.detail ?? detail; } catch { /* use status */ }
    throw new Error(detail);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}
export const api = {
  login: (username: string, password: string) => request<{ username: string; role: string }>("/api/v1/auth/login", { method: "POST", body: JSON.stringify({ username, password }) }),
  me: () => request<{ username: string; role: string }>("/api/v1/auth/me"),
  logout: () => request<void>("/api/v1/auth/logout", { method: "POST" }),
  adminUsers: () => request<Array<{ username: string; email?: string | null; role: string; active: boolean; created_at?: string | null; last_login_at?: string | null }>>("/api/v1/admin/users"),
  createAnalyst: (username: string, password: string, email?: string) => request<{ username: string }>("/api/v1/admin/users", { method: "POST", body: JSON.stringify({ username, password, email: email || null, role: "analyst" }) }),
  updateUser: (username: string, role: string, active: boolean, email?: string | null) => request<{ username: string }>(`/api/v1/admin/users/${encodeURIComponent(username)}`, { method: "PATCH", body: JSON.stringify({ role, active, email: email ?? null }) }),
  resetUserPassword: (username: string, password: string) => request<void>(`/api/v1/admin/users/${encodeURIComponent(username)}/password`, { method: "POST", body: JSON.stringify({ password }) }),
  validationRules: () => request<ValidationRule[]>("/api/v1/validation/rules"),
  validationDatasets: () => request<ValidationDataset[]>("/api/v1/validation/datasets"),
  validationRun: () => request<ValidationRun>("/api/v1/validation/runs", { method: "POST" }),
  validationRuns: () => request<ValidationRun[]>("/api/v1/validation/runs"),
  validationReport: (id: string, format: "json" | "markdown" = "json") => request<ValidationRun | string>(`/api/v1/validation/runs/${encodeURIComponent(id)}/report?format=${format}`),
  downloadValidationReport: async (id: string, format: "json" | "markdown" = "markdown") => {
    const response = await fetch(`${baseUrl}/api/v1/validation/runs/${encodeURIComponent(id)}/report?format=${format}`, { credentials: "include" });
    if (!response.ok) throw new Error(`Report export failed (${response.status}).`);
    return response.blob();
  },
  health: () => request<{ status: string }>("/health"),
  runtimeMode: () => request<RuntimeMode>("/api/v1/runtime/mode"),
  alerts: () => request<Alert[]>("/api/v1/alerts"),
  alert: (id: string) => request<Alert>(`/api/v1/alerts/${encodeURIComponent(id)}`),
  alertStatus: (id: string, status: string, note?: string) => request<Alert>(`/api/v1/alerts/${encodeURIComponent(id)}/status`, { method: "PATCH", body: JSON.stringify({ status, note }) }),
  alertAssignment: (id: string, owner: string | null) => request<Alert>(`/api/v1/alerts/${encodeURIComponent(id)}/assignment`, { method: "PATCH", body: JSON.stringify({ owner }) }),
  alertPriority: (id: string, priority: string) => request<Alert>(`/api/v1/alerts/${encodeURIComponent(id)}/priority`, { method: "PATCH", body: JSON.stringify({ priority }) }),
  alertNotes: (id: string) => request<Array<{ id: number; alert_id: string; investigation_id?: string | null; author?: string | null; note: string; created_at: string }>>(`/api/v1/alerts/${encodeURIComponent(id)}/notes`),
  addAlertNote: (id: string, note: string, investigation_id?: string) => request<unknown>(`/api/v1/alerts/${encodeURIComponent(id)}/notes`, { method: "POST", body: JSON.stringify({ note, investigation_id }) }),
  alertHistory: (id: string) => request<Array<{ id: number; alert_id: string; event_type: string; previous_value?: string | null; new_value?: string | null; actor?: string | null; timestamp: string; details?: string | null }>>(`/api/v1/alerts/${encodeURIComponent(id)}/history`),
  events: () => request<SecurityEvent[]>("/api/v1/events"),
  triage: (id: string) => request<TriageResult>(`/api/v1/alerts/${encodeURIComponent(id)}/triage`, { method: "POST" }),
  triageResult: (id: string) => request<TriageResult>(`/api/v1/alerts/${encodeURIComponent(id)}/triage`),
  forensics: (id: string) => request<ForensicAnalysis>(`/api/v1/alerts/${encodeURIComponent(id)}/forensics`, { method: "POST" }),
  investigate: (id: string) => request<InvestigationReport>(`/api/v1/alerts/${encodeURIComponent(id)}/investigate`, { method: "POST" }),
  investigation: (id: string) => request<InvestigationReport>(`/api/v1/investigations/${encodeURIComponent(id)}`),
  investigationsList: (limit: number = 50, offset: number = 0) => request<InvestigationListResponse>(`/api/v1/investigations?limit=${limit}&offset=${offset}`),
  investigationSummary: () => request<InvestigationSummary>("/api/v1/investigations/summary"),
  investigations: (id: string) => request<InvestigationReport[]>(`/api/v1/alerts/${encodeURIComponent(id)}/investigations`),
  threatIntel: (id: string) => request<ThreatIntelligenceResult>(`/api/v1/alerts/${encodeURIComponent(id)}/threat-intelligence`),
  manualThreatIntel: (value: string, indicator_type: string = "auto") => request<import("../types/api").ThreatIndicator[]>("/api/v1/threat-intelligence/lookup", { method: "POST", body: JSON.stringify({ value, indicator_type }) }),
  manualThreatIntelResults: () => request<import("../types/api").ThreatIndicator[]>("/api/v1/threat-intelligence/manual"),
  threatIntelStatus: () => request<{ providers: import("../types/api").ThreatIntelProviderStatus[]; overview: import("../types/api").ThreatIntelOverview }>("/api/v1/threat-intelligence/status"),
  threatIntelConsole: () => request<{ records: import("../types/api").ThreatIntelConsoleRecord[] }>("/api/v1/threat-intelligence/console"),
  mitreOverview: () => request<Record<string, string | number | boolean>>("/api/v1/mitre/overview"),
  mitreMatrix: () => request<import("../types/api").MitreMatrix>("/api/v1/mitre/matrix"),
  mitreTechnique: (id: string) => request<import("../types/api").MitreTechnique>(`/api/v1/mitre/techniques/${encodeURIComponent(id)}`),
  detectionCoverage: () => request<{ covered_rules: number; mapped_techniques: string[]; rules: unknown[] }>("/api/v1/detection/coverage"),
  detectionRules: () => request<Array<{ rule_id: string; name: string; description: string; severity: string; status: string; version: string; telemetry_requirements: string[]; mitre_techniques: string[]; false_positive_considerations: string[]; rationale: string; investigation_steps: string[] }>>("/api/v1/detection/rules"),
  huntingSearch: (filters: { indicator?: string; host?: string; process?: string }) => request<{ total: number; matches: Array<Record<string, string | null>> }>("/api/v1/hunting/search?" + new URLSearchParams(filters).toString()),
  iocExplorer: (indicator: string) => request<Record<string, unknown>>(`/api/v1/ioc/${encodeURIComponent(indicator)}/explorer`),
  investigationStoryline: (id: string) => request<{ summary: string; events: Array<{ timestamp: string; event_id: string; process: string | null; command_line: string | null }> }>(`/api/v1/investigations/${encodeURIComponent(id)}/storyline`),
  investigationEvidenceQuality: (id: string) => request<{ confidence: number; label: string; components: Record<string, number | boolean> }>(`/api/v1/investigations/${encodeURIComponent(id)}/evidence-quality`),
  investigationCopilot: (id: string) => request<{ summary: string; observations: string[]; questions: string[]; recommended_actions: string[] }>(`/api/v1/investigations/${encodeURIComponent(id)}/copilot`),
  saveInvestigationAssessment: (id: string, assessment: { conclusion: string; status: string; uncertainty: string; next_actions: string[]; assessor: string }) => request<import("../types/api").InvestigationReport>(`/api/v1/investigations/${encodeURIComponent(id)}/assessment`, { method: "PUT", body: JSON.stringify(assessment) }),
};
