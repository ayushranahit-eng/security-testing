# MongoDB Data Model

This is the first MongoDB version for the security scanner backend. Keep it simple.

The backend uses four collections:

1. `users`
2. `account_plans`
3. `scans`
4. `findings`

MongoDB is optional during local development. If `MONGODB_URI` is not set, the scanner keeps using the current in-memory scan flow.

## Environment File

Create or edit `backend/.env`:

```env
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=security_testing
DEFAULT_USER_FIRST_NAME=Ayush
DEFAULT_USER_LAST_NAME=Rana
DEFAULT_USER_EMAIL=ayush@example.com
DEFAULT_COMPANY_NAME=Hands In Technology
DEFAULT_COMPANY_URL=
DEFAULT_ACCOUNT_PLAN=Basic
```

For hosted MongoDB, paste your remote connection string into `MONGODB_URI`.

`backend/.env` is ignored by Git and should not be committed.

## Collection: `users`

Stores the customer/account owner.

```json
{
  "_id": "ObjectId",
  "first_name": "Ayush",
  "last_name": "Rana",
  "email": "ayush@example.com",
  "company_name": "Hands In Technology",
  "company_url": null,
  "account_plan_id": "ObjectId",
  "created_at": "ISODate",
  "updated_at": "ISODate"
}
```

Indexes:

- Unique `email`.

## Collection: `account_plans`

Stores available account plans.

```json
{
  "_id": "ObjectId",
  "name": "Basic",
  "no_of_scans_available": 5,
  "created_at": "ISODate",
  "updated_at": "ISODate"
}
```

Indexes:

- Unique `name`.

Default seeded plan:

```json
{
  "name": "Basic",
  "no_of_scans_available": 5
}
```

Product plan positioning used by the frontend:

| Plan | Intended Use | Scan Limit |
| --- | --- | --- |
| Basic | Free public URL scanning and reports | 5 scans |
| Advanced | Active Monitoring and production drift visibility | 50 public URL scans |
| Premium | Deep Scan and source-code/repository security workflows | Unlimited public URL scans |

Only Basic is seeded automatically in the current backend. Advanced and Premium are currently frontend/product positioning and should be added to `account_plans` when billing or plan switching is implemented.

## Collection: `scans`

Stores each scan job and its final raw result.

```json
{
  "_id": "ObjectId",
  "user_id": "ObjectId",
  "scan_id": "existing-backend-scan-id",
  "domain": "example.com",
  "url": "https://example.com",
  "status": "queued",
  "config": {
    "headless": true,
    "max_pages": 20,
    "max_depth": 2
  },
  "progress": {
    "current_step": "Queued",
    "pages_found": 0,
    "forms_found": 0,
    "inputs_found": 0,
    "buttons_found": 0,
    "api_calls_found": 0,
    "findings_found": 0
  },
  "summary": {
    "pages": 3,
    "forms": 1,
    "inputs": 58,
    "api_calls": 10,
    "findings": 10,
    "risk_score": 6.2,
    "severity_counts": {
      "critical": 0,
      "high": 2,
      "medium": 2,
      "low": 6,
      "info": 0
    }
  },
  "events": [],
  "raw_result": {},
  "error": null,
  "created_at": "ISODate",
  "started_at": "ISODate",
  "completed_at": "ISODate",
  "updated_at": "ISODate"
}
```

Status values:

- `queued`
- `running`
- `completed`
- `failed`

Indexes:

- Unique `scan_id`.
- `user_id + created_at`.
- `domain + created_at`.
- `status + created_at`.

## Collection: `findings`

Stores each vulnerability/finding as a separate document.

```json
{
  "_id": "ObjectId",
  "user_id": "ObjectId",
  "scan_id": "existing-backend-scan-id",
  "domain": "example.com",
  "url": "https://example.com",
  "vulnerability_name": "Missing CSP Header",
  "severity": "medium",
  "status": "open",
  "description": "Content-Security-Policy header was not present.",
  "evidence": {},
  "remediation": "Add a strict Content-Security-Policy header.",
  "raw": {},
  "fingerprint": "sha256",
  "created_at": "ISODate",
  "updated_at": "ISODate"
}
```

Severity values:

- `critical`
- `high`
- `medium`
- `low`
- `info`

Finding status values:

- `open`
- `fixed`
- `false_positive`
- `accepted_risk`

Indexes:

- `scan_id`.
- `user_id + status + severity`.
- `domain + status`.
- `fingerprint`.

## API Endpoints Added

```text
GET /me
GET /account-plans
GET /scans?limit=20
GET /findings?limit=50&status=open&severity=high&domain=example.com
```

`GET /me` also returns:

```json
{
  "scans_used": 0,
  "scans_left": 5
}
```

For this first version, `scans_used` is counted across all stored scans for the default user. It is not monthly billing-grade quota logic yet.

Frontend usage:

- The dashboard topbar uses `/me` to display current plan and scans left.
- The Scan a Domain page uses `/scans` to show recent scans from MongoDB.
- The Vulnerabilities page uses `/findings` to show findings across all domains and stored scans.
- If MongoDB is unavailable, `/scans` falls back to in-memory jobs and `/findings` returns an empty list.

Existing scan endpoints remain the same:

```text
POST /scan
GET  /scan/status/{scan_id}
GET  /scan/result/{scan_id}
```

## Current Backend Behavior

When MongoDB is configured:

1. Backend startup creates indexes.
2. Backend startup seeds a default `Basic` account plan.
3. Backend startup seeds a default user.
4. Starting a scan creates a document in `scans`.
5. Live scan progress updates the same `scans` document.
6. When the scan finishes, the raw result is stored in `scans.raw_result`.
7. Every scanner finding is inserted into `findings`.
8. `/me` recalculates `scans_used` and `scans_left` from the stored scans and current account plan.

When MongoDB is not configured:

1. Existing in-memory scan behavior continues.
2. `/me` returns the default local profile.
3. `/account-plans` returns the default Basic plan.
4. `/scans` returns current in-memory scan jobs.
5. `/findings` returns an empty list.

## Why `scans` Is Needed

The user asked for three main data areas: users, account plans, and findings.

`scans` is also required because findings alone cannot cleanly answer:

- Which domain was scanned when?
- Is a scan queued, running, completed, or failed?
- How many scans has the user used?
- What was the scan progress?
- What raw result should be used to regenerate a report?
- What should appear in recent scan history?

So the minimum practical schema is four collections.
