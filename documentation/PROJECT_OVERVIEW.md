# Project Overview

## What This Repository Does

This project is an automated web security scanner. It crawls a target website, discovers pages and frontend elements, captures API calls triggered by browser interaction, and runs common security checks.

The current backend is a FastAPI service powered by Playwright.

## Current Capabilities

- Crawls internal pages from a target URL.
- Discovers forms, inputs, buttons, and links.
- Interacts with pages to reveal hidden workflows and API calls.
- Checks risky HTTP methods and TRACE support.
- Fingerprints likely frontend, API, CMS, and server technologies.
- Tests likely GraphQL endpoints for public introspection exposure.
- Performs small API throttling checks on discovered API-like endpoints.
- Reviews POST forms for likely CSRF protection gaps.
- Reviews response headers for server and framework disclosure banners.
- Scans rendered HTML for exposed keys, tokens, and secret-looking values.
- Scans first-party JavaScript for exposed secrets and tokens.
- Pulls certificate transparency records to inventory public subdomains.
- Alerts on newly observed CT-backed subdomains compared with the last baseline.
- Checks discovered subdomains for common takeover-style dangling-hosting fingerprints.
- Checks whether JavaScript source maps are publicly accessible.
- Probes sibling public API versions around discovered versioned endpoints.
- Tests low-risk file-style parameters for path traversal file-read signals.
- Checks for directory listing exposure and direct access to common internal paths.
- Tests a small common-port list for extra public-facing services.
- Pulls passive public host-intelligence data for the resolved IP and derives a basic exposure score.
- Checks public breach catalogs for domain-linked breach history.
- Checks whether the domain appears to publish DNSSEC records.
- Tracks certificate expiry, header regressions, and exposed-asset drift across repeat scans using a local baseline snapshot.
- Tests whether CRLF input can inject unexpected response headers.
- Collects passive domain age and parking posture signals.
- Probes error handling for stack traces, SQL errors, and debug leakage.
- Tests redirect-style parameters for open redirect behavior.
- Tests client-side fragment handling for DOM-based XSS behavior.
- Tests low-risk parameters and forms for reflected XSS behavior.
- Tests low-risk forms for stored XSS persistence behavior.
- Tests low-risk parameters and safe form flows for SQL injection signals.
- Checks required security headers.
- Reviews cookie security flags.
- Validates SSL/TLS certificate status and checks for weak TLS protocol or cipher support.
- Probes common sensitive paths like `.env`, `.git/config`, Swagger files, admin paths, and config files.
- Analyzes CORS misconfigurations.
- Produces raw JSON, readable JSON, and text reports.

## Repository Layout

```text
security-testing/
+-- backend/
|   +-- main.py
|   +-- config.py
|   +-- models.py
|   +-- core/
|   +-- scanner/
|   +-- tests/
+-- documentation/
+-- .gitignore
```

## Backend Modules

- `backend/main.py`: FastAPI app, scan endpoints, job tracking, downloads.
- `backend/core/engine.py`: Main async scan workflow using Playwright.
- `backend/core/reporter.py`: Readable JSON and text report generation.
- `backend/scanner/`: Individual scanner checks for crawling, headers, cookies, SSL, certificate transparency, subdomain takeover signals, baseline-driven alerts, passive host intelligence, domain breach history, server-header disclosure, domain posture, DNSSEC, open ports, HTTP methods, technology fingerprinting, GraphQL exposure, rate limiting, CSRF risk, HTML secrets, JavaScript secrets, source maps, API version exposure, path traversal, HTTP response splitting, directory listing, forced browsing, verbose errors, CORS, sensitive paths, open redirect validation, DOM-based XSS validation, reflected XSS validation, stored XSS validation, SQL injection validation, and interaction.
- `backend/config.py`: Default scan limits, timeouts, headers, test input values, and unsafe button skip rules.

## Current Stage

The scanner now covers reconnaissance, security misconfiguration detection, exposure checks, transport-layer hardening checks, and an initial active validation layer. The next high-value additions would be stronger authenticated testing, deeper access-control checks, SSRF-style validation, stronger SQLi confirmation logic, and library/CVE correlation.
