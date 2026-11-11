# Deployment

## Environment

Copy `.env.example` to `.env` outside version control and set a strong `SHERLOCK_ANALYST_PASSWORD`. Use `SHERLOCK_SECURE_COOKIES=true` behind HTTPS. Restrict `SHERLOCK_CORS_ORIGINS` to the deployed frontend origin.

## Backend

From the repository root:

```powershell
Set-Location .\backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The backend working directory matters for the default relative SQLite URL. Prefer an absolute `SHERLOCK_DATABASE_URL` in hosted environments.

## Frontend

```powershell
Set-Location .\frontend
npm ci
npm run build
```

Serve `frontend/dist` with an SPA fallback to `index.html`, and proxy `/api` and `/health` to the backend.

## Persistence and recovery

SQLite must be placed on a persistent volume. Before upgrades, stop writes and copy the database file:

```powershell
New-Item -ItemType Directory -Force .\backups | Out-Null
Copy-Item .\data\sherlock.db .\backups\sherlock-$(Get-Date -Format yyyyMMdd-HHmmss).db
```

Restore by stopping the backend, replacing the database file from a verified backup, and rerunning the health and smoke checks. Do not use an ephemeral filesystem for a public demonstration that must retain investigations.

If the configured bootstrap password is unknown or has changed after the analyst
account was created, stop the backend and run this local recovery command from the
backend project environment:

```powershell
Set-Location .\backend
..\.venv\Scripts\python.exe -m app.cli reset-analyst-password
```

The command reads the replacement password through hidden terminal prompts, requires
12 or more characters, updates only the configured analyst account, and invalidates
its existing sessions. It does not delete application data and never accepts a
password as a command-line argument. Restart the backend after the reset.

## Smoke test and rollback

Run `.\scripts\smoke_test.ps1 -BaseUrl https://your-api.example`. Roll back by redeploying the previous application image/build and restoring the last verified database backup if a schema or application regression is detected. No public deployment is performed by this repository.
