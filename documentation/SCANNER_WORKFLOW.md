# Scanner Workflow

## High-Level Flow

1. Receive a target URL and scan settings from the API.
2. Build scan configuration from defaults plus request values.
3. Launch Chromium through Playwright.
4. Load the target page.
5. Crawl internal links within configured depth and page limits.
6. Collect forms, inputs, buttons, and links.
7. Interact with safe form fields and buttons.
8. Capture frontend-triggered API calls.
9. Run security checks.
10. Generate raw and readable results.

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

The current scanner does not yet perform deep active exploit validation. Future modules can add:

- JavaScript secret scanning
- Technology fingerprinting
- Library and CVE detection
- SQL injection testing
- Reflected XSS testing
- Authentication and authorization checks
