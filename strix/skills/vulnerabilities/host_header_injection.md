---
name: host-header-injection
description: Host, forwarding-header, and absolute-URL construction security testing
---

# Host Header Injection

Host-related input can influence routing, link generation, cache keys,
password-reset URLs, tenant selection, and upstream service choice.

## Inspect

- `Host`, forwarded-host/proto headers, absolute-form request targets, and
  duplicate or conflicting host values.
- Password-reset, invitation, canonical-link, redirect, and callback URL
  generation.
- Reverse-proxy trust boundaries and allowlists for internal service routing.
- Cache behavior; pair with `cache_poisoning` when a response is shared.

## Safe Proof

Use a controlled hostname or harmless marker. Establish that the application,
not merely an edge proxy error page, consumed the value. Do not send recovery
links to third parties or cause requests to internal systems without explicit
authorization.
