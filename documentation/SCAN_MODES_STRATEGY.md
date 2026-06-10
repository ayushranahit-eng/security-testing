# Scan Modes Strategy

This document defines how the scanner should handle different types of websites based on access requirements.

## Why This Matters

Not all websites can be assessed the same way.

In practice, the scanner will encounter three common target types:

1. public websites
2. websites that require credentials
3. websites that require credentials but allow new account creation

Each type changes what the scanner can see, what it can test, and how much confidence the results should carry.

## The Three Website Types

### 1. Public Website

This is a website that can be scanned without login.

Examples:

- marketing sites
- public portals
- landing pages
- public dashboards
- public documentation

Best coverage areas:

- security headers
- cookie flags
- SSL/TLS
- CORS
- sensitive path exposure
- JavaScript secrets
- source maps
- public API discovery
- public XSS/open redirect/SQLi signals
- HTTP methods
- verbose errors
- technology fingerprinting
- forced browsing

This is the scanner's current strongest mode.

### 2. Authenticated Website

This is a website where meaningful application content only appears after login.

Examples:

- SaaS dashboards
- admin panels
- customer portals
- internal business tools
- user account systems

Why it matters:

Many important vulnerabilities only exist after authentication.

Examples:

- CSRF in state-changing forms
- IDOR/BOLA
- privilege escalation
- session management issues
- stored XSS in user-generated content
- insecure account settings workflows
- internal API exposure

Without authenticated scanning, the system only sees the public edge of the application.

### 3. Signup Then Scan

This is a website where a new user can create an account and then access authenticated features.

Examples:

- free-trial SaaS products
- user portals with open registration
- customer onboarding applications

Why it matters:

This mode allows the scanner to:

- create a fresh user
- scan a real post-registration journey
- discover user-only flows
- test default privilege boundaries

This is highly valuable, but more complex than standard login support.

## Recommended Product Model

The scanner should support explicit scan modes instead of assuming all targets behave the same way.

Recommended modes:

- `public`
- `authenticated`
- `signup_then_scan`

This is better than trying to force a single generic scan flow to cover every target.

## What Each Mode Covers

### Public Mode

Use when:

- no credentials are required
- only external attack surface is needed

Covers best:

- reconnaissance
- exposure checks
- misconfiguration checks
- initial active validation

Limitations:

- does not see internal user flows
- does not cover role-based behavior
- cannot validate session-dependent issues deeply

### Authenticated Mode

Use when:

- the user can provide test credentials
- the target application contains important content after login

Covers best:

- internal pages and forms
- authenticated APIs
- session behavior
- CSRF
- stored XSS in actual workflows
- privilege and access-control signals

Limitations:

- requires secure handling of credentials
- login workflows vary by application
- may still miss registration-only or verification-only paths

### Signup Then Scan Mode

Use when:

- a new account can be created automatically
- the application is intended for normal user onboarding

Covers best:

- new-user flows
- onboarding paths
- default user permissions
- self-service account features

Limitations:

- sign-up automation is fragile across apps
- captcha, email verification, OTP, and invite-only systems may block automation
- requires stronger account lifecycle management

## Recommended Rollout Order

### Phase 1: Public Mode

This already exists and should continue improving.

### Phase 2: Authenticated Mode

This should be the next major capability.

Why:

- high-value vulnerabilities often live behind login
- easier than fully automated account creation
- unlocks much deeper enterprise testing

### Phase 3: Signup Then Scan Mode

This should come after authenticated scanning is stable.

Why:

- much more variation in registration flows
- more operational complexity
- often requires email or verification handling

## Suggested Backend Design

The scan configuration should eventually support something like:

```json
{
  "scan_mode": "public",
  "login_url": "",
  "username": "",
  "password": "",
  "signup_url": "",
  "post_login_indicator": "",
  "post_auth_start_url": ""
}
```

Later enhancements may include:

- username selector
- password selector
- submit selector
- login strategy
- MFA/OTP handling hooks
- session cookie hints
- logout indicator

## Suggested Frontend Design

The frontend should eventually let the user choose:

- public scan
- authenticated scan
- signup then scan

For authenticated mode, the UI can collect:

- login URL
- username/email
- password
- optional advanced selectors

For signup mode, the UI can collect:

- signup URL
- whether manual verification is needed
- whether email verification is required

## Security Handling Requirements

If credentials are introduced, the product must treat them carefully.

Important requirements:

- do not log credentials in plain text
- do not include credentials in saved reports
- do not echo credentials in frontend or backend debug output
- minimize credential persistence
- clearly identify whether a scan was public or authenticated

## Reporting Implications

Reports should clearly state which mode was used.

Example:

- Scan mode: Public
- Scan mode: Authenticated
- Scan mode: Signup Then Scan

This matters because users may otherwise assume deeper coverage than the scan actually had.

## Trust Boundary

Without authenticated scanning, users should not assume that:

- internal application security was assessed
- user-only APIs were tested
- role or privilege issues were covered
- session-dependent risks were fully reviewed

This should be stated clearly in future reporting and product messaging.

## Final Recommendation

The long-term scanner should support all three website types.

Recommended implementation order:

1. public scan
2. authenticated scan
3. signup then scan

This gives the best balance of:

- practical value
- engineering effort
- testing depth
- product maturity
