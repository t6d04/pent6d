---
name: triage-validation
description: Evidence-first gate for deciding whether a security candidate is reportable, unresolved, or ruled out
---

# Triage Validation

A scanner signal, a version banner, or an error difference is a candidate,
not a vulnerability report. Apply this gate before filing any report.

## Reportability Gate

Answer every question with evidence from this scan:

1. **Scope** — Is the affected asset explicitly authorized, and is this test
   allowed by the engagement rules?
2. **Reachability** — Can an attacker reach the behavior with the stated
   prerequisites and a concrete request or source path?
3. **Control** — Does the evidence show attacker control of the relevant
   input, rather than a generic error or a scanner heuristic?
4. **Impact** — What confidentiality, integrity, or availability impact was
   actually demonstrated? Do not substitute a possible chain for proof.
5. **Reproduction** — Can another tester replay the minimum sequence from
   the captured request, baseline, and stated preconditions?
6. **Counterevidence** — What control, limitation, or failed test could make
   the conclusion weaker or false?

## Outcomes

- All answers supported: file the appropriate report with evidence.
- The candidate is plausible but an answer is missing: record coverage as
  `needs_follow_up`, naming the precise proof gap. If there is no supported
  way to perform the proposed check at all, record an `informational`
  observation with the exact method gap instead of implying that the
  candidate was tested.
- A concrete control prevents the effect on every reachable path: record it
  as `ruled_out` with the control and its location or observed behavior.

Never close a candidate merely because a tool did not find a payload, a
version looks patched, or an endpoint was difficult to test.

## Evidence Contract

For dynamic findings, preserve both a benign baseline and the proving request
via `http_exchange_ids`. State the endpoint, method, mutated input,
authentication state, observable difference, and request preconditions. For
source-only findings, preserve the source-to-sink path and explain why runtime
proof was unavailable.

## Known-CVE Gate

A product name or version banner alone does not prove a CVE applies. Confirm
the exact product, affected version range, required feature or configuration,
and target reachability. Use authoritative vendor/advisory research when
available; otherwise leave the CVE identifier out and record the gap. In deep
mode, route plausible in-scope CVEs through `cve_exploit_validation` and close
each candidate as confirmed, ruled out, or inconclusive. Persist the matching
coverage outcome as `reported`, `ruled_out`, or `needs_follow_up`; coverage does
not accept `inconclusive` directly.
