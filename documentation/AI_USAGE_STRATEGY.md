# AI Usage Strategy

This document defines where AI should be used in the security scanning platform, where it should not be used, and how it should be introduced safely.

## Short Position

AI should improve the system's:

- analysis
- prioritization
- correlation
- reporting
- adaptive recommendations

AI should **not** replace the core detection engine for most scanner checks.

The scanner should remain primarily:

- deterministic where possible
- evidence-driven
- reproducible
- explainable

## Core Principle

The platform should be designed in three layers:

1. **Detection Layer**
2. **Rule And Scoring Layer**
3. **AI Analysis Layer**

### 1. Detection Layer

This is where the actual scanning happens:

- crawling
- page discovery
- form discovery
- input discovery
- API capture
- header checks
- cookie checks
- SSL checks
- CORS checks
- sensitive path probing
- XSS checks
- SQL injection heuristics
- open redirect validation
- JavaScript secret scanning

This layer should stay mostly rule-based and deterministic.

### 2. Rule And Scoring Layer

This layer converts raw evidence into structured findings:

- severity mapping
- confidence assignment
- category mapping
- known weak configuration logic
- exposure classification
- risk scoring

This layer should remain explicit and auditable.

### 3. AI Analysis Layer

This layer should sit on top of the scanner and help answer:

- which findings matter most?
- which findings combine into a larger attack path?
- which findings may be false positives?
- what should developers fix first?
- how should the report be explained to technical and non-technical readers?

## Where AI Is A Strong Fit

### 1. Finding Prioritization

AI can help sort findings based on:

- exploitability context
- exposure level
- attack chaining potential
- business impact

Example:

- Missing CSP alone may be medium risk.
- Missing CSP + reflected XSS + weak cookies can represent much higher practical risk.

### 2. Executive Summaries

AI is a strong fit for:

- concise report summaries
- leadership summaries
- client-friendly explanations
- action-first language

### 3. Remediation Guidance

AI can transform raw findings into:

- practical fix recommendations
- grouped remediation plans
- platform-specific implementation guidance
- developer-readable next steps

### 4. Finding Correlation

AI can identify when multiple lower-level issues combine into a larger risk.

Examples:

- open redirect + OAuth weakness
- JavaScript secret exposure + API discovery
- weak headers + XSS signal
- SSRF + cloud metadata access

### 5. False Positive Review

AI can act as a second-pass reviewer for:

- suspicious but uncertain responses
- reflection behavior
- noisy JavaScript token matches
- low-confidence anomaly-based findings

This should reduce analyst noise, not silently suppress evidence.

### 6. Adaptive Scan Suggestions

AI can recommend deeper checks based on context, for example:

- this route looks like GraphQL
- this form looks authentication-related
- this workflow looks high risk
- this finding should trigger more focused testing

## Where AI Should Not Be The Main Mechanism

These checks should stay deterministic first:

- security header detection
- SSL certificate checks
- cookie flag checks
- CORS behavior checks
- HTTP method checks
- TRACE checks
- sensitive path probing
- source map exposure checks
- directory listing checks
- redirect behavior checks
- GraphQL introspection checks
- rate-limiting measurement

These are better handled by direct logic than by model judgment.

## What AI Should Never Be Allowed To Do Alone

AI should not be the only authority for:

- confirming that a vulnerability exists
- declaring an application secure
- suppressing a finding without traceable evidence
- deciding exploitability without evidence context
- replacing manual validation for critical findings

AI output should be treated as:

- advisory
- analytical
- prioritization-oriented
- evidence-interpreting

not as absolute proof.

## Safe Product Positioning

When AI is added, the platform should still be described as:

> An evidence-driven security scanning platform with AI-assisted analysis and reporting.

Avoid claims such as:

- AI proves exploitability
- AI guarantees security
- AI replaces penetration testing
- AI removes the need for validation

## Recommended AI Roadmap

### Phase 1: Report Quality

Use AI for:

- executive summaries
- remediation explanation
- technical-to-business translation

This is the safest and fastest high-value use.

### Phase 2: Risk Prioritization

Use AI for:

- ordering findings
- identifying likely high-impact issues
- grouping related findings

### Phase 3: Correlation And Attack Paths

Use AI for:

- chaining issues into practical attack scenarios
- blast radius estimation
- mitigation sequencing

### Phase 4: Adaptive Recommendations

Use AI for:

- suggesting follow-up checks
- highlighting suspicious workflows
- guiding deeper scans

### Phase 5: Analyst Assistance

Use AI for:

- false positive review
- noisy result classification
- report enrichment

## Best Long-Term Architecture

The best long-term design is:

- deterministic scanner core
- structured evidence model
- rule-based finding generation
- AI overlay for interpretation

That keeps the product:

- trustworthy
- explainable
- easier to audit
- safer to use in real security work

## Final Position

AI should be used as a force multiplier for the scanner, not as a substitute for the scanner.

The strongest use of AI in this platform is:

- explaining findings
- prioritizing findings
- correlating findings
- improving usability of security output

The strongest use of deterministic logic remains:

- vulnerability detection
- response measurement
- protocol and browser behavior checks
- reproducible evidence collection
