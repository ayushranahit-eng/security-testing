# Scanner Workflow

## High-Level Flow

1. Receive a target URL and scan settings from the API.
2. Build scan configuration from defaults plus request values.
3. Launch Chromium through Playwright.
4. Load the target page.
5. Crawl internal links within configured depth and page limits.
6. Collect forms, inputs, buttons, and links.
7. Run low-risk active validation checks such as open redirect, DOM-based XSS, reflected XSS, stored XSS, and SQL injection heuristics.
8. Interact with safe form fields and buttons.
9. Capture frontend-triggered API calls.
10. Run security checks and content analysis, including JavaScript secret scanning.
11. Generate raw and readable results.

## Discovery Phase

The scanner builds an attack surface inventory:

- Internal pages
- Forms
- Input fields
- Buttons
- API calls
- Cookies

This helps identify what parts of the application should be tested further.

## Security Checks

The backend currently checks:

- Security headers: CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy.
- Cookies: Secure, HttpOnly, SameSite.
- SSL/TLS: certificate validity, expiry, and trust status.
- JavaScript secrets: exposed API keys, tokens, JWT-like strings, and high-entropy assignments in first-party JS.
- Open redirects: redirect-style parameters and safe GET redirect flows.
- DOM-based XSS: client-side rendering of attacker-controlled fragment input.
- Reflected XSS: unsanitized HTML reflection in low-risk URL parameters and safe forms.
- Stored XSS: payload persistence after low-risk form submission and reload.
- SQL injection: database error leakage and strong response anomalies in low-risk GET-style flows.
- Sensitive paths: exposed env files, Git metadata, backups, Swagger/OpenAPI files, admin paths, and config files.
- CORS: wildcard origins, origin reflection, null origin, credentials issues, and risky trusted origins.

## Safety Rules

The scanner avoids clicking buttons with risky keywords such as:

- delete
- remove
- logout
- purchase
- pay
- checkout
- deactivate
- unsubscribe
- destroy

These rules are stored in `backend/config.py`.

## Output Types

- Raw JSON: complete scan data for automation.
- Readable JSON: structured report with summaries and recommendations.
- Text report: downloadable report for sharing.

## Known Gaps

The current scanner now performs an initial active validation layer, but still has important depth gaps:

- authenticated workflow testing
- stored XSS testing
- stronger SQL injection confirmation logic
- technology fingerprinting
- library and CVE detection
- authentication and authorization checks
