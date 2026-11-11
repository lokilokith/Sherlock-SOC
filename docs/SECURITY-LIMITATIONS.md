# Security and Limitations

## Access control

With authentication enabled, unauthenticated users can read synthetic demo data from a separate SQLite database but cannot import events or execute/persist triage, forensics, threat-intelligence, or investigation operations. Analyst sessions use scrypt password hashes and expiring, server-side hashed session tokens in an HttpOnly cookie. Logout revokes the session.

Set `SHERLOCK_ANALYST_PASSWORD` through the deployment secret manager. The backend fails at startup if authentication is enabled without a password.

## Data and provider boundaries

- Demo data is synthetic and must not be presented as production telemetry.
- Demo threat intelligence is mock/unavailable intelligence; unknown is not treated as malicious.
- Live provider credentials are read from provider environment variables and are not returned by the API.
- Agent outputs are schema-validated and evidence references are checked against persisted events.
- Agents do not execute commands or directly write arbitrary database records.

## Known limitations

- SQLite is suitable for local MVP and single-instance demonstrations, not concurrent multi-instance production hosting.
- A persistent volume and backup process are required for hosted SQLite.
- The current analyst model is single-user bootstrap authentication; it is not an enterprise identity provider.
- Rate limiting and multi-tenant ownership controls remain deployment-layer work.
- React Router 6.30.6 has two moderate npm advisories. The npm fix is React Router 7.18.5, a major upgrade. This Vite BrowserRouter SPA does not use SSR hydration APIs, and its tested navigation uses fixed application routes.
## Validation endpoints

Validation rules, datasets, runs, and report exports require an authenticated analyst
session. Validation history contains synthetic event fields and metrics only. The lab
does not accept arbitrary rule or dataset uploads and does not provide evidence that
SOC-001 generalizes beyond this labelled fixture set.
