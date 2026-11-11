import { AlertCircle, CheckCircle2, CircleDashed, LoaderCircle, SearchX } from "lucide-react";
import type React from "react";
import type { AgentExecutionStatus, Severity } from "../types/api";

export function SeverityBadge({ value }: { value: Severity }) {
  const key = value.toLowerCase();
  const color = key === "critical" || key === "high" ? "danger" : key === "medium" ? "warning" : key === "low" ? "info" : "muted";
  return <span className={`badge badge-${color}`}>{value}</span>;
}
export function StatusBadge({ value }: { value: string }) {
  const color = value === "completed" ? "success" : value === "failed" ? "danger" : value === "partial" ? "warning" : "info";
  return <span className={`badge badge-${color}`}>{value}</span>;
}
export function AgentStatus({ status }: { status: AgentExecutionStatus }) {
  const Icon = status.status === "completed" ? CheckCircle2 : status.status === "failed" ? AlertCircle : status.status === "running" ? LoaderCircle : CircleDashed;
  return <span className="agent-state"><Icon size={14} className={status.status === "running" ? "spin" : ""} /> {status.status}</span>;
}
export function LoadingSkeleton({ rows = 4 }: { rows?: number }) { return <div className="skeleton-stack">{Array.from({ length: rows }, (_, i) => <div className="skeleton" key={i} />)}</div> }
export function EmptyState({ title, message }: { title: string; message: string }) { return <div className="empty-state"><SearchX size={28} /><strong>{title}</strong><span>{message}</span></div> }
export function ErrorState({ message }: { message: string }) { return <div className="error-state"><AlertCircle size={20} /><span>{message}</span></div> }
export function SectionTitle({ eyebrow, title, action }: { eyebrow?: string; title: string; action?: React.ReactNode }) { return <div className="section-title"><div>{eyebrow && <span className="eyebrow">{eyebrow}</span>}<h2>{title}</h2></div>{action}</div> }
