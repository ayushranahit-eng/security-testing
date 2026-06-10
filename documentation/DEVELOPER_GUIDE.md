# Developer Guide

## What We Are Building

This repository is an enterprise-style website security scanning platform.

It is designed to:

- crawl and inspect public-facing websites
- detect security misconfigurations and exposure issues
- run controlled active checks for selected web vulnerabilities
- produce readable security reports for technical and non-technical users
- generate backend-owned PDF reports that can later be downloaded or emailed

This is not positioned as a full penetration test replacement. It is an automated security assessment system focused on:

- attack-surface discovery
- exposure detection
- defensive control validation
- early vulnerability triage
- actionable reporting

## Product Shape

The system currently has two main parts:

### 1. Backend

The backend performs the actual scan.

It is responsible for:

- crawling pages
- discovering forms, inputs, buttons, and internal links
- observing network/API requests
- running security checks
- collecting findings and evidence
- generating readable JSON and PDF reports

### 2. Frontend

The frontend is a presentation layer.

It is responsible for:

- starting scans
- showing live scan progress in plain language
- rendering the readable report
- downloading the backend-generated PDF

The frontend does not own scanning logic and should not be treated as the source of truth for findings.

## How We Are Building It

We are building the scanner in a modular, capability-based way.

### Core approach

The architecture follows three layers:

1. **Scan engine**
   - drives browser automation and crawl flow
   - coordinates discovery and active validation

2. **Scanner modules**
   - each capability lives in its own Python file where possible
   - each module performs one clear security function
   - examples: headers, cookies, CORS, XSS, SQLi, secrets, source maps

3. **Report layer**
   - converts raw scan output into structured readable analysis
   - explains impact, evidence, risk, and remediation
   - feeds both frontend preview and backend-generated PDF

## Important Engineering Principles

### 1. Separate capability files

For readability and maintainability, new security checks should usually be added as separate files in `backend/scanner/`.

Examples:

- `reflected_xss_scanner.py`
- `stored_xss_scanner.py`
- `dom_xss_scanner.py`
- `sql_injection_scanner.py`
- `auth_surface_detector.py`

### 2. Keep scanning deterministic first

The core scanner should remain mostly:

- rule-based
- protocol-aware
- browser-aware
- evidence-driven

AI can be added later for:

- prioritization
- correlation
- summarization
- remediation writing

AI should not be the only reason a vulnerability is declared real.

### 3. Reports must be analysis-first

We do not want noisy raw dumps.

Reports should explain:

- what was found
- why it matters
- evidence
- business/security impact
- likely confidence
- remediation steps
- scan coverage limitations

### 4. Tell the truth about coverage

The scanner must not imply full assurance where it only tested public scope.

If authentication surface is detected but no credentials were used, the report must clearly say:

- auth-related functionality exists
- only unauthenticated/public testing was performed
- authenticated workflows were not assessed

## Current Scan Philosophy

The scanner is strongest today at:

- public attack-surface mapping
- security header checks
- cookie flag analysis
- SSL/TLS certificate review
- CORS observations
- sensitive path probing
- JavaScript secret detection
- source map exposure
- directory listing checks
- forced browsing checks
- HTTP method and TRACE analysis
- GraphQL introspection checks
- API throttling signals
- verbose error leakage
- reflected XSS checks
- stored XSS checks
- DOM-based XSS checks
- open redirect checks
- SQL injection signals

Some checks are stronger than others. Misconfigurations and exposure issues are generally higher-confidence than deeper exploit-style findings.

## Auth And Coverage Model

We now explicitly distinguish between:

- public website scan
- authenticated application surface that exists but was not tested with credentials

Current auth logic is a coverage classifier, not a login breaker.

`auth_surface_detector.py` helps identify:

- login routes
- signup routes
- password reset flows
- auth-related forms
- password fields
- auth-related buttons
- auth-like API routes

This is used to improve reporting honesty and scan-boundary classification.

## PDF Strategy

PDF generation is owned by Python/backend, not by the frontend.

Reason:

- better consistency
- cleaner filenames
- easier download behavior
- easier future email delivery
- avoids browser print footer/path issues

Frontend previews the readable report, but the final PDF should come from backend-rendered output.

## Frontend Expectations

The frontend should:

- stay readable for technical and non-technical users
- present live scan activity in understandable language
- show evidence, impact, and remediation clearly
- avoid exposing backend implementation details unnecessarily

The frontend should not:

- invent findings
- silently transform scan meaning
- present public-only coverage as full application assurance

## How To Add A New Capability

When adding a new capability, the preferred flow is:

1. Create a new scanner file in `backend/scanner/`
2. Add a short top-of-file note describing:
   - what it checks
   - what kind of signal it provides
   - what it does not prove by itself
3. Wire it into `backend/core/engine.py`
4. Add analysis support in `backend/core/reporter.py`
5. Expose it in the frontend report if it is meaningful to users
6. Include it in the PDF report if it affects client-facing output
7. Update relevant docs in `documentation/`

## Reporting Standard

The report should feel like it came from a security engineer, but still be understandable.

That means:

- plain language first
- technical accuracy preserved
- no exaggerated certainty
- no hiding limitations
- action-oriented remediation

## Trust Boundary

This platform can uncover real issues and meaningful signals, but it should not claim:

- that a clean report means the site is secure
- that all findings are fully exploitable
- that public scanning covers authenticated workflows

Use careful wording and preserve credibility.

## Files That Matter Most

Key backend files:

- `backend/main.py`
- `backend/core/engine.py`
- `backend/core/reporter.py`
- `backend/core/pdf_report.py`
- `backend/scanner/`

Key frontend files:

- `frontend/index.html`
- `frontend/app.js`
- `frontend/styles.css`

Key documentation files:

- `documentation/CURRENT_CAPABILITIES.md`
- `documentation/TRUST_AND_CAPABILITY_BOUNDARIES.md`
- `documentation/AI_USAGE_STRATEGY.md`
- `documentation/SCAN_MODES_STRATEGY.md`

## Working Style For Future AI Assistants

If you are another Codex or AI assistant working in this repo:

- read existing scanner and reporter patterns first
- prefer adding small, separate capability files
- keep report wording honest
- do not overstate scan confidence
- preserve backend ownership of final PDF generation
- treat auth-surface detection as a coverage signal, not a confirmed vulnerability
- favor maintainability over cleverness
- update documentation when capabilities materially change
