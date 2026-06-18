# Backend API Reference

## Run Locally

Run from the backend folder:

```bash
cd backend
pip install -r requirements.txt
playwright install chromium
uvicorn main:app --reload --port 8000
```

Swagger UI:

```text
http://localhost:8000/docs
```

## Request Body

All scan endpoints accept this body:

```json
{
  "url": "https://example.com",
  "headless": true,
  "max_pages": 20,
  "max_depth": 2
}
```

## Main Scan Flow

### `POST /scan`

Starts a background scan and returns a `scan_id`.

Use this as the main frontend endpoint.

### `GET /scan/status/{scan_id}`

Returns live progress while the scan is running.

When complete:

- `readable=true`: returns engineer-readable JSON.
- `readable=false`: returns raw scan data.
- `download=true`: downloads the text report.
- `pdf=true`: downloads the PDF report.

Live status includes timing information used by the frontend:

- Before ETA is finalized: frontend shows `Calculating ETA`.
- While running with ETA: frontend shows remaining time.
- After completion: frontend shows the actual completed duration from report metadata.

## Account And Stored Data

These endpoints are used by `frontend2/` when MongoDB persistence is configured.

### `GET /me`

Returns the current seeded/default user, account plan, scan usage, and scans left.

Example fields:

```json
{
  "first_name": "Ayush",
  "last_name": "Rana",
  "email": "ayush@example.com",
  "company_name": "Hands In Technology",
  "account_plan": {
    "name": "Basic",
    "no_of_scans_available": 5
  },
  "scans_used": 1,
  "scans_left": 4,
  "persistence": "mongodb"
}
```

### `GET /account-plans`

Returns available account plans currently stored in MongoDB.

Current backend seed:

- `Basic`
- `no_of_scans_available: 5`

Advanced and Premium are currently frontend product tiers until backend plan management is expanded.

### `GET /scans`

Returns recent scan records. Used by the Scan a Domain page to show recent scans from the database.

Query:

- `limit`: default `20`, max `100`

The response excludes heavy `raw_result` payloads.

### `GET /findings`

Returns stored findings across domains and scans. Used by the Vulnerabilities page.

Query filters:

- `status`
- `severity`
- `domain`
- `limit`: default `50`, max `200`

## Hidden/Utility Endpoints

### `POST /scan/start`

Same behavior as `/scan`, but hidden from the OpenAPI schema.

### `GET /scan/result/{scan_id}`

Returns the final result after completion. If the scan is still running, it returns a conflict response.

### `POST /scan/download`

Runs a full scan and downloads raw JSON.

### `POST /scan/report`

Runs a full scan and downloads a text report.

### `GET /health`

Simple health check.

## Micro Checks

These endpoints run fast targeted checks without the full browser workflow.

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/micro/headers` | Checks required security headers |
| POST | `/micro/cookies` | Checks cookie flags from the first request |
| POST | `/micro/ssl` | Checks SSL/TLS certificate status |

## Frontend Integration Notes

- Start scans with `POST /scan`.
- Poll `GET /scan/status/{scan_id}` until status becomes completed.
- Use `readable=true` for UI display.
- Use `readable=false` if the frontend needs raw structured data.
- Use `download=true` when the user clicks a report download button.
- Use `pdf=true` when the user clicks PDF download.
- Use `GET /me` for current plan, user greeting, and scans-left display.
- Use `GET /scans` for recent scan history.
- Use `GET /findings` for cross-domain vulnerability tables.
