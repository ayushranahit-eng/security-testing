# Current Capabilities

This document summarizes what the scanner can currently detect, why each capability matters, and the security risk it helps identify.

## Capability Summary

| Capability | Importance | Impact | Risk |
| --- | --- | --- | --- |
| Security header analysis | Verifies browser-side protections are configured. | Reduces exposure to XSS, clickjacking, MIME sniffing, and downgrade attacks. | Low to Medium |
| SSL/TLS certificate and transport analysis | Confirms encrypted communication is trusted and valid, and checks for legacy TLS support and weak cipher acceptance. | Prevents user trust issues, reduces man-in-the-middle risk, and highlights outdated HTTPS hardening. | Medium to High |
| Cookie security analysis | Checks whether session cookies are protected. | Helps prevent session theft, token leakage, and cross-site request abuse. | Medium to High |
| HTTP method analysis | Reviews advertised and risky HTTP methods such as TRACE, PUT, DELETE, and PATCH. | Helps identify unnecessary protocol surface and legacy risky behavior. | Low to Medium |
| Page crawling | Maps reachable application pages. | Builds a broader attack surface inventory instead of scanning only one URL. | Informational to Medium |
| Form and input discovery | Finds user-controlled entry points. | Identifies areas that need injection, validation, and workflow testing. | Medium |
| Safe interaction testing | Interacts with pages to reveal hidden flows and API calls. | Discovers behavior that static crawling may miss. | Medium |
| API endpoint discovery | Captures frontend-triggered backend requests. | Reveals hidden or undocumented API surfaces that may need authorization testing. | Medium to High |
| Technology fingerprinting | Identifies likely frameworks, CMS markers, server technologies, and API styles. | Helps defenders understand exposed stack components and prioritize patch review. | Informational to Medium |
| GraphQL introspection checks | Tests whether GraphQL schema metadata is exposed publicly. | Helps detect schema disclosure that speeds up attacker reconnaissance. | Low to Medium |
| API rate-limit checks | Sends a small burst of requests to exposed API-like endpoints. | Helps detect missing throttling that can support brute force and scraping. | Low to Medium |
| CSRF risk detection | Reviews state-changing forms for likely anti-CSRF token presence. | Helps detect weak request-forgery protections in browser workflows. | Medium |
| Server header disclosure checks | Reviews response headers for server, runtime, proxy, and framework banners. | Helps detect technology disclosure that speeds up attacker stack profiling. | Low |
| HTML secret scanning | Detects exposed keys, tokens, and credentials rendered directly into HTML. | Helps prevent credential leakage through templates, meta tags, inline JSON, and page source. | High to Critical |
| JavaScript secret scanning | Detects exposed keys, tokens, and credentials in frontend code. | Helps prevent unauthorized API use, cloud abuse, and credential leakage from client-side assets. | High to Critical |
| Open redirect validation | Tests redirect-style parameters and flows for attacker-controlled redirects. | Helps prevent phishing, trust abuse, and token-forwarding style attacks. | Medium to High |
| DOM-based XSS validation | Tests client-side handling of attacker-controlled fragment input. | Helps identify browser-side code execution risk caused by unsafe DOM sinks. | High to Critical |
| Reflected XSS validation | Tests whether input is reflected back into the page without safe handling. | Helps identify browser-side script execution risk, session theft, and phishing overlays. | High to Critical |
| Stored XSS validation | Tests whether attacker-controlled HTML persists after submission and reload. | Helps identify persistent browser-side code execution risk affecting later viewers. | High to Critical |
| SQL injection validation | Tests low-risk parameters and forms for database error leakage and response anomalies. | Helps identify injection paths that could expose or modify database content. | High to Critical |
| Path traversal validation | Tests low-risk file-style parameters for direct filesystem-read traversal signals. | Helps detect unauthorized server file access through path normalization flaws. | High |
| API version exposure checks | Probes sibling public API versions near discovered versioned endpoints. | Helps detect stale or parallel API versions that may drift from newer security controls. | Low to Medium |
| Sensitive path probing | Tests common exposed files and admin/config paths. | Detects leaked secrets, config files, backups, API docs, and admin panels. | Medium to Critical |
| Open port checks | Tests a small common-port list for extra public-facing services. | Helps detect accidental exposure of admin, database, development, or alternate web services. | Low to Medium |
| DNSSEC checks | Checks whether the public domain publishes DNSKEY records. | Helps highlight DNS hardening gaps on production-facing domains. | Low |
| HTTP response splitting validation | Tests whether CRLF input can inject arbitrary response headers. | Helps detect cache-poisoning, header-injection, and redirect-manipulation risk. | High |
| Domain age and parking posture checks | Uses public registration-age and parking signals as passive trust context. | Helps identify newly registered or parked domains that deserve extra scrutiny. | Low |
| Certificate transparency monitoring | Pulls public CT records for the target domain. | Helps inventory public subdomains and certificate-linked exposure outside the main crawl. | Informational to Medium |
| New subdomain alerts | Compares current CT-discovered subdomains against the last saved baseline. | Helps detect new public-facing assets that may not have gone through normal review. | Low to Medium |
| Subdomain takeover checks | Tests CT-discovered subdomains for dangling third-party hosting fingerprints. | Helps detect abandoned DNS mappings that attackers may be able to claim. | High |
| SSL certificate expiry monitor | Tracks certificate expiry against a configurable renewal threshold. | Helps catch renewal risk early before browser trust breaks. | Low to Medium |
| Security header regression alerts | Compares current response headers with the previous baseline. | Helps detect when previously present protections silently disappear. | Medium |
| Exposed asset drift detection | Compares public pages and API calls with the previous baseline. | Helps detect newly exposed or unexpectedly removed public assets. | Low to Medium |
| Passive host intelligence | Queries public passive internet exposure data for the resolved host IP. | Helps reveal externally observed ports, tags, and vulnerability hints. | Low to Medium |
| Passive IP reputation heuristics | Scores public IP risk signals from passively observed exposure. | Helps triage whether the host deserves closer review. | Low to Medium |
| Domain credential leak checks | Checks public breach catalogs for domain-linked breach history. | Helps surface credential reuse and phishing pressure tied to the domain. | Medium |
| Exposure scoring | Calculates a simple passive exposure score from public host-intelligence signals. | Helps summarize how broad or noisy the public footprint looks. | Low to Medium |
| JavaScript source map checks | Tests whether `.map` files for production JavaScript are publicly accessible. | Helps detect source disclosure that reveals original code and implementation details. | Low to Medium |
| Directory listing checks | Detects directory index pages served by the web server. | Helps detect accidental exposure of file structures and forgotten assets. | Low to Medium |
| Forced browsing checks | Tests common unlinked internal/admin-style paths for direct reachability. | Helps detect internal routes that are exposed without being linked in the UI. | Low to Medium |
| Verbose error checks | Probes error responses for stack traces, SQL errors, and framework exception text. | Helps detect information leakage that assists attacker reconnaissance. | Low to Medium |
| CORS security analysis | Checks risky cross-origin trust behavior. | Finds misconfigurations that could allow malicious sites to read user data. | Medium to Critical |
| Report generation | Converts scan data into readable output. | Helps developers understand findings and decide next actions. | Operational |

## Detailed Capabilities

### Security Header Analysis

Checks for important headers such as:

- Content-Security-Policy
- X-Frame-Options
- Strict-Transport-Security
- X-Content-Type-Options
- Referrer-Policy

Importance: These headers add browser-level defenses.

Impact: Missing headers can increase exposure to XSS, clickjacking, content sniffing, weak referrer handling, and HTTPS downgrade risks.

Risk: Low to Medium, depending on the missing header and application context.

### SSL/TLS Certificate and Transport Analysis

Checks:

- certificate validity
- certificate expiry
- hostname trust
- negotiated TLS protocol
- negotiated cipher
- support for legacy TLS 1.0 and TLS 1.1
- acceptance of weak cipher suites

Importance: Users and APIs depend on trusted encrypted communication.

Impact: Invalid or expired certificates can break user trust, trigger browser warnings, and increase interception risk. Legacy protocol or weak cipher support can leave the origin compatible with transport settings that should already be retired.

Risk: Medium to High.

### Cookie Security Analysis

Checks cookie flags:

- Secure
- HttpOnly
- SameSite

Importance: Cookies often store session or authentication state.

Impact: Weak cookie settings can make session theft or cross-site attacks easier.

Risk: Medium to High.

### HTTP Method Analysis

Checks whether the origin advertises or accepts risky HTTP methods such as:

- TRACE
- PUT
- DELETE
- PATCH

Importance: Public applications should only expose the methods they actually need.

Impact: Unnecessary methods increase attack surface and may indicate weak request hardening.

Risk: Low to Medium.

### Crawling and Discovery

Discovers internal pages, links, forms, inputs, buttons, and cookies.

Importance: Security testing is only useful when the visible attack surface is mapped.

Impact: Reveals pages and workflows that may otherwise be missed.

Risk: Informational to Medium.

### Form and Interaction Analysis

Fills safe test values into inputs and interacts with buttons while avoiding risky actions like delete, logout, purchase, and unsubscribe.

Importance: Many modern applications expose behavior only after interaction.

Impact: Helps uncover hidden forms, workflows, and network activity.

Risk: Medium.

### API Endpoint Discovery

Captures API calls triggered by frontend pages and interactions.

Importance: APIs are often more security-sensitive than the UI that calls them.

Impact: Reveals undocumented endpoints that should be tested for authentication, authorization, and data exposure.

Risk: Medium to High.

### Technology Fingerprinting

Looks for public signs of:

- framework usage
- CMS markers
- server headers
- JavaScript platform signatures
- GraphQL/API style indicators

Importance: Understanding public stack indicators helps prioritize hardening and patch validation.

Impact: Exposed technology clues help attackers profile the application, but also help defenders close obvious gaps.

Risk: Informational to Medium.

### GraphQL Introspection Checks

Tests likely GraphQL endpoints with a schema introspection query.

Importance: GraphQL schemas can reveal object names, types, queries, and operations.

Impact: Public schema visibility can accelerate attacker reconnaissance and endpoint mapping.

Risk: Low to Medium.

### API Rate-Limit Checks

Sends a small burst of requests to an exposed API-like endpoint and looks for throttling signals such as:

- HTTP 429
- Retry-After headers
- request blocking patterns

Importance: Public APIs should resist brute force, scraping, and simple automation abuse.

Impact: Missing throttling can support account attacks or high-volume abuse.

Risk: Low to Medium.

### CSRF Risk Detection

Reviews discovered POST forms for likely anti-CSRF token presence and state-changing behavior.

Importance: Browser-authenticated actions need request-forgery protections.

Impact: Missing anti-CSRF controls can allow attackers to trick logged-in users into performing unwanted actions.

Risk: Medium.

### Server Header Disclosure Checks

Checks whether the origin discloses headers such as:

- `Server`
- `X-Powered-By`
- `X-AspNet-Version`
- `X-AspNetMvc-Version`
- `Via`

Importance: Public banner disclosure makes it easier to fingerprint web servers, middleware, and application runtimes.

Impact: Even when not directly exploitable, stack disclosure accelerates attacker reconnaissance and version-targeted exploit research.

Risk: Low.

### HTML Secret Scanning

Scans rendered HTML responses for:

- API keys
- JWT-like tokens
- cloud credentials
- high-entropy secrets
- inline config leaks

Importance: Secrets can leak through templates, inline JSON, meta tags, hydration data, and raw page source, not only JavaScript files.

Impact: Exposed credentials can lead to unauthorized API use, impersonation, service abuse, or downstream compromise.

Risk: High to Critical.

### JavaScript Secret Scanning

Scans first-party JavaScript files and inline scripts for:

- OpenAI-style API keys
- AWS access keys
- GitHub tokens
- Stripe keys
- Google API keys
- JWT-like tokens
- high-entropy secret assignments

Importance: Frontend JavaScript often becomes a source of accidental credential leakage.

Impact: Exposed secrets can lead to unauthorized API use, cloud abuse, service impersonation, or further compromise.

Risk: High to Critical.

### Open Redirect Validation

Tests redirect-style parameters such as:

- `redirect`
- `next`
- `returnUrl`
- `continue`
- `destination`

Importance: A trusted domain that can redirect to attacker-controlled destinations is valuable for phishing and malicious auth-flow chaining.

Impact: Attackers can abuse a legitimate domain to increase trust in phishing links or redirect users to malicious pages.

Risk: Medium to High.

### DOM-Based XSS Validation

Tests whether attacker-controlled URL fragment data is rendered into the DOM by client-side JavaScript.

Importance: DOM-based XSS can happen entirely in frontend code, even when the server never reflects the payload.

Impact: Can lead to browser-side code execution, session theft, phishing overlays, and account takeover chains.

Risk: High to Critical.

### Reflected XSS Validation

Tests low-risk URL parameters and safe form flows for unsanitized HTML reflection.

Importance: Reflected XSS is one of the most damaging browser-side issues because it executes in the victim's session context.

Impact: Can lead to session theft, malicious overlays, credential capture, and client-side account takeover chains.

Risk: High to Critical.

### Stored XSS Validation

Tests low-risk forms with a unique payload, then checks whether the payload persists after submission and reload.

Importance: Stored XSS is often more damaging than reflected XSS because later viewers can be affected without taking a special action.

Impact: Can lead to persistent session theft, administrative compromise, malicious content injection, and multi-user impact.

Risk: High to Critical.

### SQL Injection Validation

Tests low-risk GET parameters and safe search-style forms with conservative SQL payloads, then checks for:

- database error messages
- SQL exception patterns
- strong response anomalies

Importance: SQL injection remains one of the highest-impact application vulnerabilities.

Impact: A confirmed issue could expose, modify, or destroy data and may lead to authentication bypass or broader compromise.

Risk: High to Critical.

### Path Traversal Validation

Tests low-risk query parameters such as file, path, template, or download-style inputs with conservative traversal payloads.

Importance: File-oriented parameters are a common place for unsafe path joining and normalization mistakes.

Impact: Successful traversal can expose local files such as system configuration, credentials, source code, and application secrets.

Risk: High.

### API Version Exposure Checks

Checks discovered versioned API-style endpoints for sibling public versions such as `v1`, `v2`, `v3`, or `beta`.

Importance: Older or parallel API versions often drift away from current authorization, validation, and abuse controls.

Impact: Reachable legacy versions can silently expand attack surface even when the main UI uses a newer API.

Risk: Low to Medium.

### JavaScript Source Map Checks

Tests whether production JavaScript source maps are publicly accessible.

Importance: Source maps can reveal original code, comments, identifiers, and internal implementation detail.

Impact: Attackers can use source maps to understand application behavior and hidden client-side logic faster.

Risk: Low to Medium.

### Directory Listing Checks

Tests whether the web server exposes directory index pages.

Importance: Directory indexes can reveal forgotten files, asset structure, or sensitive artifacts.

Impact: Even when the files themselves are not obviously dangerous, the listing helps attackers map what exists.

Risk: Low to Medium.

### Forced Browsing Checks

Tests common internal-style and administrative-looking paths for direct unauthenticated access.

Importance: Some routes are not linked in the interface but are still reachable directly.

Impact: Can reveal exposed internal tools, documentation, consoles, or weakly protected routes.

Risk: Low to Medium.

### Verbose Error Checks

Probes error responses for:

- stack traces
- SQL exception text
- framework exception messages
- filesystem or code path leakage

Importance: Detailed error output often helps attackers refine payloads and fingerprint the stack.

Impact: Information leakage makes exploitation easier even if it is not the root vulnerability itself.

Risk: Low to Medium.

### Sensitive Path Probing

Checks common exposed paths such as:

- `.env`
- `.git/config`
- backup files
- Swagger/OpenAPI files
- admin paths
- config files
- server status/debug paths

Importance: Exposed internal files can leak secrets, infrastructure details, or admin functionality.

Impact: A successful finding can lead to credential leakage, source exposure, or direct system compromise.

Risk: Medium to Critical.

### Open Port Checks

Performs a lightweight TCP connect scan against a short list of common public ports.

Importance: Public websites sometimes expose administrative, development, or datastore services alongside the main web origin.

Impact: Extra public ports can reveal management interfaces, alternate apps, or databases that were never meant to be internet-facing.

Risk: Low to Medium.

### DNSSEC Checks

Checks whether the public domain appears to publish DNSKEY records.

Importance: DNSSEC improves trust in DNS responses by adding authenticity signals at the zone level.

Impact: Missing DNSSEC is not always a direct vulnerability, but it does represent weaker DNS hardening for production-facing properties.

Risk: Low.

### HTTP Response Splitting Validation

Tests whether CRLF input in low-risk query parameters can inject unexpected response headers.

Importance: Header-injection flaws can affect browsers, proxies, caches, and downstream security controls.

Impact: Successful response splitting can support cache poisoning, redirect manipulation, cookie confusion, or header-based abuse.

Risk: High.

### Domain Age and Parking Posture Checks

Uses passive public signals such as:

- recent domain registration age
- parking-related homepage content

Importance: Domain posture helps defenders triage whether an internet-facing property looks mature, intentionally live, or still in a parked state.

Impact: Very new or parked domains deserve extra validation before they are treated as stable production assets.

Risk: Low.

### Certificate Transparency Monitoring

Pulls public certificate transparency records for the target domain and extracts observed subdomains from issued certificates.

Importance: CT data often reveals public-facing assets that are not obvious from the main website crawl.

Impact: Helps defenders inventory shadow assets, staging systems, and certificate-linked subdomain growth.

Risk: Informational to Medium.

### New Subdomain Alerts

Compares the current CT-discovered subdomain set against the last locally saved baseline.

Importance: New public subdomains often appear before they have gone through the same hardening and review process as the main site.

Impact: Highlights public attack-surface drift at the DNS and certificate layer.

Risk: Low to Medium.

### Subdomain Takeover Checks

Tests a limited set of CT-discovered subdomains for common dangling-hosting fingerprints such as unclaimed GitHub Pages, Heroku, S3, or Azure endpoints.

Importance: Abandoned DNS mappings can let attackers host content on a trusted domain.

Impact: Takeover-prone subdomains can support phishing, impersonation, and trust abuse under the victim domain.

Risk: High.

### SSL Certificate Expiry Monitor

Tracks the current certificate against a configurable renewal threshold and saves the latest baseline for future comparison.

Importance: Expiring certificates can break user trust and cause avoidable incidents if they are only noticed at the last moment.

Impact: Gives earlier warning than a one-time expiry check alone.

Risk: Low to Medium.

### Security Header Regression Alerts

Compares the current response header posture against the previous saved baseline.

Importance: Teams sometimes remove or break security headers during CDN, reverse-proxy, or framework changes without noticing immediately.

Impact: Detects silent hardening regressions instead of only reporting the current moment in isolation.

Risk: Medium.

### Exposed Asset Drift Detection

Compares the currently discovered public pages and captured API calls with the previous baseline.

Importance: Public attack surface changes over time, and new routes may bypass the normal review path.

Impact: Highlights new or missing public assets that may deserve manual review.

Risk: Low to Medium.

### Passive Host Intelligence

Queries public passive host intelligence for the resolved public IP address and reviews:

- observed ports
- hostnames
- passive tags
- published vulnerability hints

Importance: Attackers use passive internet data sources during reconnaissance, so defenders benefit from seeing the same broad picture.

Impact: Helps reveal exposure that may not be obvious from the main page crawl alone.

Risk: Low to Medium.

### Passive IP Reputation Heuristics

Builds a lightweight reputation-style signal from passively observed risky ports, tags, and vulnerabilities.

Importance: Not every public IP with extra exposure is critical, but clustered passive signals usually deserve closer review.

Impact: Helps triage which hosts look noisier or riskier from the outside.

Risk: Low to Medium.

### Domain Credential Leak Checks

Checks public breach-catalog data for breach records linked to the scanned domain.

Importance: Domain-linked breach history increases credential reuse, phishing, and password-spraying pressure against people associated with that domain.

Impact: Helps teams understand when public breach history should raise the urgency of login hardening and credential defenses.

Risk: Medium.

### Exposure Scoring

Calculates a simple passive exposure score from public host-intelligence signals such as:

- number of observed ports
- risky port types
- passive vulnerability hints
- risky public tags

Importance: A single summarized score helps triage broad public footprint risk without replacing the underlying evidence.

Impact: Makes passive exposure easier to compare between repeated scans.

Risk: Low to Medium.

### CORS Security Analysis

Checks for wildcard origins, credential misuse, origin reflection, null origin trust, and risky third-party trust.

Importance: CORS controls which websites can read browser-based API responses.

Impact: Misconfigured CORS can allow malicious websites to read sensitive user data.

Risk: Medium to Critical.

## Current Position

The scanner currently provides strong coverage for:

- Attack surface mapping
- Security misconfiguration detection
- Information disclosure checks
- Frontend secret exposure checks
- HTTP method and TRACE checks
- Technology fingerprinting
- GraphQL introspection checks
- API throttling checks
- CSRF risk detection
- Redirect validation
- DOM-based XSS validation
- Reflected XSS validation
- Stored XSS validation
- Initial SQL injection heuristics
- Source map checks
- Directory listing checks
- Forced browsing checks
- Verbose error checks
- Browser and API discovery
- Developer-readable reporting

The next major improvement area is deeper authenticated validation, stronger exploit confirmation logic, SSRF and access-control testing, and technology/CVE correlation.
