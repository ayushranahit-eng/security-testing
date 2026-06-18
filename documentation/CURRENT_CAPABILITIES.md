# Current Capabilities

This document explains what the scanner can really do today from a normal URL scan, what confidence each capability carries, and where readers should not over-assume coverage.

## Short Version

The system is a real public-scope web security scanner. It can crawl a target URL with Playwright, discover public pages and browser-visible attack surface, capture frontend-triggered requests, run exposure and misconfiguration checks, perform conservative active validation for selected vulnerability classes, and generate readable reports.

It is strongest as:

- a public attack-surface discovery tool
- a misconfiguration and exposure scanner
- a frontend secret and sensitive-file detector
- an initial vulnerability triage layer
- a repeatable baseline monitor for public surface drift

It is not yet:

- a full penetration test replacement
- an authenticated application scanner
- a role/permission testing engine
- a complete exploit-confirmation engine
- proof that a clean site is secure

## Scan Mode Covered Today

Current URL scanning is best described as:

```text
unauthenticated_public_scan
```

The scanner can only test what is publicly reachable without credentials. If it detects login, signup, password reset, or auth-like API routes, it reports that authenticated functionality appears to exist, but it does not fully assess the post-login application.

Default scan limits are currently:

- `max_pages`: 20
- `max_depth`: 2
- active validation against discovered public pages
- a short list of public ports and sensitive paths
- lightweight API/login abuse probes

## Capability Confidence

| Confidence | Capability Type | What This Means |
| --- | --- | --- |
| High | Direct observations and exposure checks | Usually actionable when detected. Examples: missing headers, exposed sensitive files, weak cookie flags, TLS issues, readable source maps, JavaScript secrets. |
| Medium | Initial active validation signals | Useful security signals, but critical findings should be manually reproduced. Examples: reflected XSS, DOM XSS, stored XSS, SQLi anomaly, open redirect, login abuse signal. |
| Low / Contextual | Passive, heuristic, or broad posture signals | Helpful for triage, but not proof of exploitation. Examples: technology fingerprinting, domain age, passive host intelligence, DNSSEC, public breach catalog matches. |

## What It Actually Checks

### Attack Surface Discovery

The scanner uses Playwright to load the site like a browser and discover:

- public internal pages
- links
- forms
- input fields
- textareas
- buttons
- cookies
- browser network requests
- frontend-triggered API-like calls

It also performs limited safe interaction with visible controls and form fields. It avoids destructive-looking buttons such as delete, logout, purchase, checkout, deactivate, unsubscribe, wipe, destroy, and similar actions.

Confidence: High for discovered public surface, limited by crawl depth, page count, JavaScript behavior, and whether a flow requires authentication.

### Security Headers

Checks whether the first loaded response includes:

- `Content-Security-Policy`
- `X-Frame-Options`
- `Strict-Transport-Security`
- `X-Content-Type-Options`
- `Referrer-Policy`

Confidence: High for the tested response.

Limitations: This is not a full per-route header audit unless those routes are separately loaded and analyzed elsewhere.

### Cookie Flags

Checks browser-collected cookies for:

- `Secure`
- `HttpOnly`
- `SameSite`

The scanner separates likely tracking/third-party cookies from possible session/application cookies where possible.

Confidence: High for observed cookies.

Limitations: It cannot evaluate cookies that only appear after login or deeper workflows.

### SSL/TLS

Checks:

- certificate validity
- certificate expiry
- negotiated TLS protocol
- negotiated cipher
- legacy TLS 1.0 / 1.1 support
- acceptance of a small set of weak cipher suites

Confidence: High for the target hostname tested.

Limitations: This is not a full SSL Labs-style transport audit across every CDN edge or hostname.

### HTTP Methods

Uses `OPTIONS` and `TRACE` against the origin to identify:

- advertised risky methods
- TRACE exposure

Confidence: Medium to High for the origin.

Limitations: It does not prove every advertised method is usable on every application route.

### Server Header Disclosure

Checks response headers such as:

- `Server`
- `X-Powered-By`
- `X-AspNet-Version`
- `X-AspNetMvc-Version`
- `Via`
- `X-Generator`

Confidence: High for observed headers.

Risk: Usually low by itself, but useful for attacker reconnaissance and stack profiling.

### Sensitive Path Probing

Requests a curated list of common public paths, including:

- `.env`
- `.git/HEAD`
- `.git/config`
- backup SQL/archive files
- Swagger/OpenAPI files
- Actuator endpoints
- `phpinfo.php`
- server status pages
- config files
- admin paths
- common metadata files

Readable 2xx-style responses are treated as exposure. HTTP 403 is treated as a blocked/detected route, not confirmed readable exposure.

Confidence: High when readable sensitive content is detected.

Limitations: The list is finite and does not discover every possible sensitive file.

### CORS Analysis

Sends crafted `Origin` headers and checks for:

- wildcard `Access-Control-Allow-Origin`
- wildcard plus credentials
- reflected arbitrary origins
- reflected origins with credentials
- accepted `null` origin
- absence of CORS headers

Confidence: High for observed headers on the tested URL.

Important interpretation: No CORS headers are usually the browser-safe default, not automatically a vulnerability. Risk increases when arbitrary origins are allowed or reflected, especially with credentials.

### JavaScript, HTML, And Rendered DOM Secret Scanning

Scans first-party JavaScript files, inline scripts, raw HTML, and browser-rendered DOM for:

- OpenAI-style API keys
- AWS access keys
- GitHub tokens
- Stripe keys
- Google API keys
- JWT-like tokens
- high-entropy secret assignments

Confidence: Medium to High depending on token type.

Limitations: Pattern and entropy scanning can produce false positives and false negatives. Any live-looking credential should be rotated and manually validated.

### JavaScript Source Maps

Checks discovered first-party JavaScript files for reachable `.map` files.

Confidence: High when a source map is reachable.

Risk: Usually source disclosure rather than direct compromise, but it can expose original code, comments, identifiers, and hidden client-side logic.

### Technology Fingerprinting

Looks for public indicators such as:

- server headers
- `X-Powered-By`
- WordPress markers
- Next.js markers
- Angular markers
- React/Vue hints
- WordPress REST API
- GraphQL route hints

Confidence: Low to Medium.

Limitations: This is heuristic reconnaissance. It should not be used by itself for CVE claims or patch decisions.

### GraphQL Introspection

Tests common GraphQL paths and discovered GraphQL-like URLs with an introspection query.

Confidence: High when schema metadata is returned.

Limitations: It does not evaluate GraphQL authorization, resolver-level access control, query complexity limits, or business logic.

### API Rate-Limit Probe

Selects one discovered first-party API-like endpoint and sends a small burst of requests, looking for:

- HTTP 429
- `Retry-After`
- obvious throttling behavior

Confidence: Low to Medium.

Limitations: This is a tiny abuse-resistance signal, not a brute-force, distributed, or production-grade rate-limit assessment.

### Login Abuse Probe

If an obvious public login form is found, the scanner sends a small number of invalid login attempts and checks for:

- CAPTCHA
- lockout wording
- cooldown wording
- HTTP 429-style throttling

Confidence: Medium when clear protection is observed or clearly absent in the limited probe.

Limitations: It does not prove credential-stuffing resilience. It does not test distributed attacks, account-specific lockouts, MFA quality, password policy, session security, or post-login behavior.

### CSRF Risk Review

Reviews discovered public POST forms for obvious anti-CSRF token hints in hidden inputs.

Confidence: Low to Medium.

Limitations: This is token-presence and workflow-shape analysis only. It does not prove exploitability and does not detect all server-side CSRF defenses.

### Open Redirect Validation

Tests redirect-like query parameters and safe GET form flows with an attacker-controlled absolute URL.

Confidence: High when the browser lands on the attacker-controlled target.

Limitations: Only tests discovered public parameters/forms and a known list of redirect-style names.

### Reflected XSS Validation

Tests existing query parameters and low-risk forms with unique marker HTML. A finding occurs when the marker appears unsanitized in the DOM/HTML.

Confidence: Medium to High.

Limitations: This detects unsafe HTML reflection signals. It does not execute JavaScript payloads or prove every browser exploit chain.

### DOM-Based XSS Validation

Uses URL-fragment marker payloads and checks whether client-side code renders the marker into the DOM.

Confidence: Medium to High when detected.

Limitations: This is a focused fragment-based signal. It does not exhaustively test every DOM sink, source, route, or client-side state.

### Stored XSS Validation

Submits marker HTML into low-risk forms and checks whether the marker persists after submission and reload.

Confidence: Medium when detected.

Limitations: The scanner intentionally avoids risky forms and only tests a small number of low-risk public forms. It does not provide deep stored-XSS coverage across authenticated or complex workflows.

### SQL Injection Signals

Tests low-risk GET parameters and safe search-style forms with conservative SQL payloads and checks for:

- database error patterns
- SQL/database exception wording
- strong response-length anomalies
- navigation errors that suggest backend SQL/database failure

Confidence: Medium when database errors are observed; lower when only response anomalies are observed.

Limitations: This is not full SQL injection exploitation. It does not dump data, infer boolean/time-based injection deeply, bypass WAFs, or prove exploitability beyond the observed signal.

### Path Traversal Validation

Tests file/path/download-style query parameters with conservative traversal payloads and looks for strong file-read evidence such as:

- `/etc/passwd` markers
- Windows `win.ini` markers

Confidence: High when evidence is detected.

Limitations: Only tests discovered query parameters and a small payload list.

### HTTP Response Splitting

Injects CRLF into selected query parameters and checks whether a custom response header appears.

Confidence: High when the injected header is observed.

Limitations: Only tests discovered/relevant public parameters.

### Directory Listing

Requests directory candidates derived from crawled URLs and looks for directory index markers such as `Index of /` or `Parent Directory`.

Confidence: High when markers are found.

Limitations: Only candidate directories derived from crawled pages are tested.

### Forced Browsing

Requests a short configured list of internal-looking paths such as:

- `/admin`
- `/dashboard`
- `/internal`
- `/debug`
- `/api/docs`
- `/swagger`
- `/actuator`
- `/graphql`

Confidence: Medium.

Limitations: A reachable route is not automatically sensitive. Manual context is required.

### Verbose Error Leakage

Requests likely error paths and malformed query input, then looks for:

- stack traces
- exception text
- SQL errors
- framework/debug output
- filesystem/code path clues

Confidence: Medium to High when explicit error text is found.

Limitations: Only a small number of probes are sent.

### Open Port Checks

Performs TCP connect checks against a short list of common public ports such as:

- 21, 22, 80, 443
- 3000, 5000, 8000, 8080, 8443
- 3306, 5432, 6379, 9200, 27017

Confidence: High for the tested hostname and port list.

Limitations: This is not a full network scan.

### DNSSEC

Checks whether the apparent base domain publishes DNSKEY records.

Confidence: Medium.

Limitations: Base-domain extraction is best effort. Some public suffix cases may need manual review.

### Domain Posture

Checks best-effort passive domain posture:

- registration age via RDAP
- parking markers in homepage content

Confidence: Low to Medium.

Limitations: This is context for triage, not a vulnerability by itself.

### Certificate Transparency

Queries certificate transparency records for the apparent base domain and extracts observed subdomains.

Confidence: Medium when records are retrieved.

Limitations: Depends on public CT query availability and best-effort base-domain extraction.

### New Subdomain Alerts

Compares current CT-discovered subdomains with the previous local baseline.

Confidence: Medium.

Limitations: Only useful after at least one prior baseline exists.

### Subdomain Takeover Fingerprints

Tests a limited number of CT-discovered subdomains for common dangling-hosting fingerprints, including providers such as GitHub Pages, Heroku, S3, and Azure App Service.

Confidence: Medium when CNAME and body fingerprint align.

Limitations: This is fingerprint-based and does not claim or exploit the subdomain.

### Passive Host Intelligence

Resolves the target hostname to an IP address and queries Shodan InternetDB for:

- observed ports
- hostnames
- CPEs
- tags
- vulnerability identifiers

It also calculates a basic exposure score from observed ports, vulnerability hints, risky ports, and risky tags.

Confidence: Low to Medium.

Limitations: Passive data may be stale, incomplete, or unavailable. Treat as enrichment, not definitive proof.

### Domain Credential Leak Catalog

Checks XposedOrNot public breach catalog data for breach records linked to the scanned domain.

Confidence: Low to Medium.

Limitations: It checks public breach records by domain. It does not search every possible leaked employee credential or private breach dataset.

### Baseline Monitoring

Stores and compares local scan baselines for:

- SSL expiry
- security header regression
- public page drift
- API call drift
- CT subdomain drift

Confidence: Medium to High after repeated scans.

Limitations: First scan creates the baseline. Meaningful drift detection starts on later scans.

### Report Generation

Generates:

- raw JSON
- readable JSON
- text reports
- backend-owned PDF reports

The report layer turns raw scan output into findings with impact, confidence, evidence, and remediation language.

## What The Scanner Does Not Fully Cover Yet

These are explicit current gaps:

- authenticated workflow scanning
- role-based access-control testing
- IDOR/BOLA detection
- privilege escalation testing
- business logic testing
- deep session management review
- complete CSRF exploit validation
- deep stored-XSS coverage across complex workflows
- deeper SQL injection confirmation, boolean/time-based testing, and exploitation
- SSRF validation
- XXE validation
- file upload abuse validation
- library/CVE correlation
- distributed or production-grade abuse/rate-limit testing
- full network inventory

## Product Positioning

Good wording:

- automated public website security assessment
- public attack-surface scanner
- exposure and misconfiguration scanner
- evidence-based vulnerability signals
- initial active validation
- manual validation recommended for critical active findings

Avoid wording:

- guaranteed security scan
- complete penetration test replacement
- full exploit confirmation
- proves the site is secure
- complete authenticated application assessment

## Practical Interpretation

If a high-confidence exposure finding appears, such as a readable `.env`, exposed source map, weak cookie flag, missing critical header, or live secret, treat it as actionable.

If an active validation finding appears, such as XSS, SQLi, open redirect, or login abuse, treat it as a meaningful security signal and manually reproduce before making final exploitability claims.

If no findings appear, interpret the result as:

```text
No issue was detected in the tested public scope.
```

Do not interpret it as:

```text
The website is secure.
```
