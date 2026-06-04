# Security Scanner API

Playwright-based web security scanner exposed as a FastAPI service.  
Crawls a target URL, interacts with forms, captures API calls, and checks
security headers, cookies, and SSL — then returns a human-readable report.

## Setup

```bash
pip install -r requirements.txt
playwright install chromium
```

## Run locally

```bash
# from the security-testing/ directory
uvicorn main:app --reload --port 8000
```

Swagger UI → `http://localhost:8000/docs`

---

## Endpoints

### Background scan (recommended)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/scan/start` | Start a scan in the background, returns `scan_id` |
| GET | `/scan/status/{scan_id}` | Live progress while running; readable JSON report when done |
| GET | `/scan/result/{scan_id}` | Final result (only available after completion) |

**Query params for status/result:**

| Param | Default | Description |
|-------|---------|-------------|
| `readable` | `true` | Engineer-readable JSON with commentary and next steps |
| `download` | `false` | Download the `.txt` report file instead |

### One-shot (blocking) endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/scan` | Alias for `/scan/start` |
| POST | `/scan/download` | Run scan, download `.json` file |
| POST | `/scan/report` | Run scan, download `.txt` report |

### Micro-checks (fast, no browser)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/micro/headers` | Check security headers only |
| POST | `/micro/cookies` | Check cookie flags only |
| POST | `/micro/ssl` | Check SSL certificate only |

---

## Request body (all POST endpoints)

```json
{
  "url": "https://example.com",
  "headless": true,
  "max_pages": 20,
  "max_depth": 2
}
```

---

## Usage flow

```bash
# 1. Start a scan
curl -X POST http://localhost:8000/scan/start \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}' 
# → returns { "scan_id": "abc123", "status": "queued", ... }

# 2. Poll for live status (readable by default)
curl http://localhost:8000/scan/status/abc123
# While running → live metrics + events log
# When done     → full engineer-readable JSON report

# 3. Download the text report
curl http://localhost:8000/scan/status/abc123?download=true -o report.txt

# 4. Get raw JSON data
curl http://localhost:8000/scan/status/abc123?readable=false
```

---

## Readable JSON report (sample)

When a scan completes, `/scan/status/{id}` returns structured, narrated JSON:

```json
{
  "scan_metadata": { "status": "✅ Scan Completed Successfully" },
  "executive_summary": {
    "scope": { "pages_crawled": 1, "api_endpoints_detected": 4 },
    "findings_summary": { "status": "🟢 Minor issues only", "total_findings": 1 }
  },
  "security_analysis": {
    "http_headers": {
      "status": "❌ Issues Found",
      "missing_headers": [
        { "header": "content-security-policy", "status": "✗ FAIL",
          "recommendation": "Add 'content-security-policy' header..." }
      ]
    },
    "ssl_certificate": { "status": "✅ VALID", "days_remaining": 52 }
  },
  "detailed_findings": [
    { "engineer_notes": "During testing, I found 4 security headers missing..." }
  ],
  "next_steps": {
    "immediate_actions": ["✅ No immediate critical actions required"],
    "recommendations": ["🔍 18 input fields identified — conduct injection and XSS testing"]
  }
}
```

---

## Project structure

```
security-testing/
├── main.py              # FastAPI app + all endpoints
├── config.py            # Default scan configuration
├── models.py            # Pydantic request/response models
├── requirements.txt
├── .gitignore
├── core/
│   ├── engine.py        # Async scan orchestrator (Playwright)
│   └── reporter.py      # Text report + readable JSON generator
└── scanner/
    ├── crawler.py       # Page crawling, link discovery, element collection
    ├── interaction.py   # Form interaction engine
    ├── headers.py       # Security headers checker
    ├── cookies.py       # Cookie flag analyser
    └── ssl_check.py     # SSL certificate checker
```
