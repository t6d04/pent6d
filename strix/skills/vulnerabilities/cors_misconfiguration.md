---
name: cors-misconfiguration
description: Cross-origin resource sharing analysis for credentialed data exposure and unsafe origin validation
---

# CORS Misconfiguration

CORS is impactful only when a browser from an attacker-controlled origin can
read a sensitive response in a victim's authenticated context.

## Check

- Origin reflection, overly broad pattern matching, `null` origin handling,
  and scheme/port/subdomain parsing.
- `Access-Control-Allow-Credentials` combined with an origin that an attacker
  can control.
- Preflight behavior versus the actual request, and differences by endpoint,
  method, and content type.
- Whether cookies are actually sent under the configured SameSite policy.

## Proof Standard

Use a harmless authenticated test account and a minimal browser proof that
reads a restricted response. Headers alone, public data, or a request blocked
by browser cookie policy do not establish a CORS vulnerability. Capture both
the preflight and the data-bearing response where applicable.
