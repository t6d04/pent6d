---
name: scope-triage
description: Authorization-aware triage of reconnaissance results before they become active testing targets
---

# Reconnaissance Scope Triage

Reconnaissance can discover names, IPs, certificates, repositories, and
third-party services that resemble the original target. Discovery is not
authorization to test them.

## Classify Every Candidate Asset

For each discovered asset, retain its source and assign one state:

- **In scope** — directly matches an authorized target or an explicitly
  authorized wildcard/range.
- **Needs confirmation** — ownership or inclusion is plausible but not stated.
- **Out of scope** — third-party, shared-hosting neighbor, unrelated sibling,
  excluded environment, or asset outside the agreed boundary.

Only the first state may be handed to an active-testing agent. The second may
be kept as a passive recon observation; do not probe, fuzz, authenticate, or
attempt exploitation until authorization is supplied.

## Attribution Is Not Scope

Certificate SANs, common ASNs, shared IPs, CNAMEs, branding, and code
references are useful attribution clues. None independently authorizes an
asset. CDN edges and cloud-provider addresses are especially prone to false
ownership conclusions.

`alive` is a service-state claim, not a discovery claim. A real origin response
(including 401, 403, 404, or 5xx) marks the host alive; DNS, CT, certificates,
portal links, and other passive evidence remain unknown until probed. A local
proxy error page does not prove the target is alive or dead, so retain unknown
and retry with a direct, scheme-correct probe. The recon runtime projects an
observed service state back onto the matching host record for a consistent
inventory.

## Handoff Record

Before spawning hunters, write the authorized asset list, exclusions,
evidence of scope, discovered route/host inventory, and unresolved ownership
questions into the threat model or a shared note. Subagents must not expand
their own host scope from a discovered lead.
