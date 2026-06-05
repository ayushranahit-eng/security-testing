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
