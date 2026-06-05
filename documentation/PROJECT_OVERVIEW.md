# Project Overview

## What This Repository Does

This project is an automated web security scanner. It crawls a target website, discovers pages and frontend elements, captures API calls triggered by browser interaction, and runs common security checks.

The current backend is a FastAPI service powered by Playwright.

## Current Capabilities

- Crawls internal pages from a target URL.
- Discovers forms, inputs, buttons, and links.
- Interacts with pages to reveal hidden workflows and API calls.
- Checks required security headers.
- Reviews cookie security flags.
- Validates SSL/TLS certificate status.
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
- `backend/scanner/`: Individual scanner checks for crawling, headers, cookies, SSL, CORS, sensitive paths, and interaction.
- `backend/config.py`: Default scan limits, timeouts, headers, test input values, and unsafe button skip rules.

## Current Stage

The scanner already covers the reconnaissance and security misconfiguration layer. The next high-value additions would be active vulnerability checks such as JavaScript secret scanning, technology fingerprinting, SQL injection testing, and reflected XSS testing.
