# Technical Decisions

- Keep FastAPI, React/Vite, SQLite, SQLAlchemy, and the existing coordinator because the MVP already has stable contracts and tests.
- Use deterministic detection before agent analysis so an LLM cannot create an alert or bypass evidence validation.
- Use an additive SQLite schema for the single-analyst MVP. A hosted multi-instance deployment should approve a separate database migration rather than silently switching engines.
- Use scrypt and server-side hashed expiring sessions in an HttpOnly cookie instead of placing bearer tokens in browser storage.
- Keep React Router 6.30.6. The available audit remediation is a major React Router 7 upgrade, which requires a separate compatibility review.
- Treat unknown threat intelligence as unknown and preserve missing-evidence explanations in the unified report.
