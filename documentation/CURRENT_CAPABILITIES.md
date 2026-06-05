# Current Capabilities

This document summarizes what the scanner can currently detect, why each capability matters, and the security risk it helps identify.

## Capability Summary

| Capability | Importance | Impact | Risk |
| --- | --- | --- | --- |
| Security header analysis | Verifies browser-side protections are configured. | Reduces exposure to XSS, clickjacking, MIME sniffing, and downgrade attacks. | Low to Medium |
| SSL/TLS certificate validation | Confirms encrypted communication is trusted and valid. | Prevents user trust issues and reduces man-in-the-middle risk. | Medium to High |
| Cookie security analysis | Checks whether session cookies are protected. | Helps prevent session theft, token leakage, and cross-site request abuse. | Medium to High |
| Page crawling | Maps reachable application pages. | Builds a broader attack surface inventory instead of scanning only one URL. | Informational to Medium |
| Form and input discovery | Finds user-controlled entry points. | Identifies areas that need injection, validation, and workflow testing. | Medium |
| Safe interaction testing | Interacts with pages to reveal hidden flows and API calls. | Discovers behavior that static crawling may miss. | Medium |
| API endpoint discovery | Captures frontend-triggered backend requests. | Reveals hidden or undocumented API surfaces that may need authorization testing. | Medium to High |
| JavaScript secret scanning | Detects exposed keys, tokens, and credentials in frontend code. | Helps prevent unauthorized API use, cloud abuse, and credential leakage from client-side assets. | High to Critical |
| Open redirect validation | Tests redirect-style parameters and flows for attacker-controlled redirects. | Helps prevent phishing, trust abuse, and token-forwarding style attacks. | Medium to High |
| DOM-based XSS validation | Tests client-side handling of attacker-controlled fragment input. | Helps identify browser-side code execution risk caused by unsafe DOM sinks. | High to Critical |
| Reflected XSS validation | Tests whether input is reflected back into the page without safe handling. | Helps identify browser-side script execution risk, session theft, and phishing overlays. | High to Critical |
| Stored XSS validation | Tests whether attacker-controlled HTML persists after submission and reload. | Helps identify persistent browser-side code execution risk affecting later viewers. | High to Critical |
| SQL injection validation | Tests low-risk parameters and forms for database error leakage and response anomalies. | Helps identify injection paths that could expose or modify database content. | High to Critical |
| Sensitive path probing | Tests common exposed files and admin/config paths. | Detects leaked secrets, config files, backups, API docs, and admin panels. | Medium to Critical |
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

### SSL/TLS Certificate Validation

Checks certificate validity, expiry, hostname trust, and SSL status.

Importance: Users and APIs depend on trusted encrypted communication.

Impact: Invalid or expired certificates can break user trust, trigger browser warnings, and increase interception risk.

Risk: Medium to High.

### Cookie Security Analysis

Checks cookie flags:

- Secure
- HttpOnly
- SameSite

Importance: Cookies often store session or authentication state.

Impact: Weak cookie settings can make session theft or cross-site attacks easier.

Risk: Medium to High.

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
- Redirect validation
- DOM-based XSS validation
- Reflected XSS validation
- Stored XSS validation
- Initial SQL injection heuristics
- Browser and API discovery
- Developer-readable reporting

The next major improvement area is deeper authenticated validation, stored XSS coverage, stronger SQLi confirmation logic, and technology/CVE detection.
