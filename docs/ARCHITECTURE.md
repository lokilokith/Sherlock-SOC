# SHERLOCK Architecture

SHERLOCK is an evidence-backed SOC investigation platform for synthetic Sysmon-style telemetry.

```text
Sysmon JSON
    |
    v
FastAPI import -> Pydantic normalization -> deterministic SOC-001 detection
    |                                      |
    v                                      v
SQLite evidence store                persisted alerts
                                           |
                                           v
                    deterministic coordinator
                  /           |              \
             Triage        Forensics      Threat Intel
                  \           |              /
                   evidence-reference validation
                              |
                              v
                   unified investigation report
```

The backend owns normalization, detection, persistence, agent invocation, output validation, and scoring. The React/Vite frontend reads the API and presents alerts, events, specialist output, evidence references, and analyst actions.

The public demo surface is read-only and uses a separate synthetic SQLite database. Analyst operations and analyst reads use the analyst database behind expiring HttpOnly cookie sessions. Demo providers are deterministic and do not make paid model calls. Live providers are selected only when `SHERLOCK_AGENT_MODE=live`.
## Detection validation

The protected `/api/v1/validation` surface runs the authoritative SOC-001 evaluator
against a version-controlled synthetic dataset. It writes only serialized validation
reports to `validation_runs`; production events, alerts, investigations, and AI
providers are not involved.
