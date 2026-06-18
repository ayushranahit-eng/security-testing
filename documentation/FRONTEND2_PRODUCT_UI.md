# Frontend2 Product UI

`frontend2/` is the current React + Vite product UI prototype for Security Tool.

It is separate from the older static frontend and is intended for testing the SaaS-style user experience around the scanner backend.

## Run Locally

Start the backend first:

```powershell
cd backend
uvicorn main:app --reload --port 8000
```

Then start the frontend:

```powershell
cd frontend2
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

The Vite proxy maps:

```text
/api -> http://localhost:8000
```

## Current Flow

1. Public landing page opens first.
2. Login/Create Account calls `GET /api/me`.
3. If the backend responds, the user can enter the signed-in dashboard.
4. The dashboard loads current user, plan, scans-left count, recent scans, and findings from backend APIs.

This is not real password authentication yet. It is a product gate around the current seeded/default backend user.

## Main Screens

### Landing Gate

File:

```text
frontend2/src/LandingGate.jsx
```

Purpose:

- Public marketing/entry screen.
- Login and create-account UI.
- Verifies account data through `GET /api/me`.
- Shows MongoDB/memory mode through backend response.
- Lets the user enter the dashboard after verification.

### Dashboard

File:

```text
frontend2/src/App.jsx
```

Purpose:

- Greets the user by first name.
- Shows all-time scan history stored in browser history for dashboard summary.
- Shows current plan and scans-left count in the top navigation from `GET /api/me`.
- Links to scan workflow, vulnerabilities, Active Monitoring, Deep Scan, and pricing.

### Scan A Domain

Purpose:

- Starts scans through `POST /api/scan`.
- Polls live status through `GET /api/scan/status/{scan_id}`.
- Shows live metrics: pages, forms, inputs, API calls, findings, and ETA.
- Shows `Calculating ETA` until backend ETA is available.
- Shows `Completed in ...` after a scan completes.
- Downloads PDF reports through `GET /api/scan/status/{scan_id}?pdf=true`.
- Shows recent scans from `GET /api/scans?limit=12`.
- Falls back to local browser scan history if the database has no scans.

### Vulnerabilities

Purpose:

- Shows vulnerabilities across all domains and all stored scans.
- Loads data from `GET /api/findings?limit=200`.
- Displays findings in a table.
- Supports filtering by:
  - search text
  - severity
  - status
  - domain
- Expandable rows show description, URL, remediation, and evidence JSON.

### Pricing

Pricing opens as a full page, not inside the dashboard shell.

It is opened by upgrade buttons only. It is not shown as a sidebar item.

Plans:

| Plan | Positioning | Scan Limit |
| --- | --- | --- |
| Basic | Free public URL scanning and reports | 5 scans |
| Advanced | Active Monitoring and production drift visibility | 50 public URL scans |
| Premium | Deep Scan and source-code/repository security workflows | Unlimited public URL scans |

The pricing page includes a Contact Sales option for custom volume, team access, security review workflows, and onboarding support.

### Active Monitoring

Plan gate:

```text
Advanced Plan
```

Purpose:

- Continuous browser-side and public exposure monitoring.
- Tracks frontend changes such as newly exposed scripts, source maps, API routes, and sensitive paths.
- Alerts on security header regressions, TLS posture changes, exposed assets, and public attack-surface drift.
- Provides a dummy four-line install script to place before the closing `</head>` tag.

Current state:

- UI-only locked module.
- Not implemented as a backend monitoring service yet.

### Deep Scan

Plan gate:

```text
Premium Plan
```

Purpose:

- Source-code and repository security scanning.
- Shows command examples for:
  - Linux server over SSH
  - Git Bash/local repository
  - CI/scripted usage

Intended checks:

- Hardcoded secrets, API keys, tokens, private keys, `.env` files.
- Dependency CVEs from npm, Python, and lockfiles.
- SQL injection risk patterns.
- Unsafe HTML rendering.
- Command execution risk.
- SSRF sinks.
- Weak authentication logic.
- Docker/config/deployment risk signals.

Current state:

- UI-only locked module.
- The backend does not yet implement source-code/repository scanning.

## Backend Dependencies

The frontend expects these backend endpoints:

```text
GET  /me
GET  /scans
GET  /findings
POST /scan
GET  /scan/status/{scan_id}
```

MongoDB should be configured if the user wants persistent scan history and vulnerabilities:

```text
backend/.env
MONGODB_URI=<hosted Mongo URI>
MONGODB_DATABASE=security_testing
```

If MongoDB is not configured:

- Scans still run using in-memory backend jobs.
- Recent scans are limited to the current backend process.
- Vulnerabilities page returns no stored findings.
