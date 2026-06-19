# Scope And Limitations

## In Scope

This scanner checks files at rest.

It can scan:

```text
source code
config files
Dockerfile
Kubernetes YAML
Terraform HCL
CI/CD workflows
dependency manifests
Git metadata/history when gitleaks is available
static web/API risk patterns
static auth/session/JWT risk patterns
static AI/LLM integration hints
```

## Out Of Scope

This scanner does not actively attack or browse a website.

It does not do:

```text
confirmed live XSS exploitation
confirmed live CSRF exploitation
confirmed live SSRF exploitation
confirmed IDOR/BOLA testing
rate-limit testing
open port scanning
TLS/cipher scanning
DNS takeover checks
cloud account API checks
business logic testing
authenticated user-flow testing
browser automation
Shodan/Censys/passive recon
WAF bypass testing
request smuggling testing
```

## Important Limitation

Source-code scanning finds risk patterns.

It cannot always prove exploitability.

Example:

```text
The scanner may find redirect(request.args.get("next")).
That is a risky open redirect pattern.
But a developer still needs to confirm whether validation happens elsewhere.
```

v3 includes broader static coverage for items such as CSRF-disabled routes, SSRF-prone server requests, open redirects, wildcard CORS, JWT mistakes, source maps, debug routes, IaC mistakes, and LLM output rendering. These are still static signals. They should be reviewed by a developer or tester before being treated as confirmed exploitable issues.

## Best Use

Use this scanner as:

```text
pre-deployment source review
CI/CD security gate
server-side code audit
early warning system
client security health check
```

It should complement, not replace:

```text
manual pentesting
external web scanning
cloud security review
secure code review
runtime testing
```
