---
name: waf_evasion
description: Controlled WAF fingerprinting and parser-differential validation for in-scope web targets
---

# WAF Evasion and Backend Differential Testing

Use this skill when a WAF, CDN rule, API gateway, bot challenge, or filtering
layer is observed or suspected. The objective is not to defeat a provider for
its own sake; it is to determine whether a security-relevant input reaches an
in-scope backend despite an enforcement layer.

## Fingerprint Before Evasion

- Capture a benign baseline, a harmless invalid request, and a single known
  block/control response. Compare status, headers, body markers, cookies,
  timing, and connection behavior.
- Use `wafw00f` or equivalent fingerprinting as a lead only. A CDN error,
  Caido/proxy failure, rate limit, or application validation error is not WAF
  evidence by itself.
- Identify which layer responded and whether the backend can be observed
  through an authorized alternate host, API version, or route. Never disable a
  WAF or alter production policy to make a test pass.

## Bounded Variant Matrix

Start with one harmless marker or a read-only test for the relevant risk, then
change one representation dimension per request:

- percent and double encoding, Unicode/canonicalization, case, whitespace,
  comments, and equivalent separators;
- JSON, form, multipart, query, path, and observed content-type parser
  differences;
- duplicate parameters, arrays/objects versus scalars, parameter ordering,
  and method or version parity when the application exposes those variants;
- path normalization and proxy/origin route differences only when both are
  explicitly in scope.

Do not use destructive payloads, credential spraying, shell deployment, data
exfiltration, request-smuggling campaigns, or high-volume evasion sprays.
Honor the scan rate/concurrency budget and stop on instability or state
changes.

## Validation Gate

A WAF bypass requires all of the following:

1. The same semantic security-relevant input is blocked or challenged in the
   baseline form.
2. A single controlled variant reaches the same in-scope backend behavior.
3. The result demonstrates an unauthorized security consequence, not merely a
   `200`, different error, reflected marker, or route existence.
4. The WAF/backend distinction and the exact variant are replayable.

If only the filter differs but no vulnerability is demonstrated, record a
defense-in-depth observation or coverage note, not a vulnerability report.
Preserve baseline and proving request IDs and record the WAF product/version
only when evidenced.
