---
name: input_filter_bypass
description: Canonicalization, parser-differential, and validation-boundary testing for input filters
---

# Input Filter and Validation Bypass

Use this skill when an endpoint filters, validates, sanitizes, normalizes, or
allowlists attacker-controlled input. Pair it with the concrete sink skill
(`sql_injection`, `xss`, `ssrf`, `path_traversal_lfi_rfi`, file upload, or
command injection); this skill finds representation gaps and does not treat a
filter difference as an impact by itself.

## Reconnaissance

Map the full path from client to sink: proxy/WAF, framework parser, middleware,
schema validator, sanitizer, serializer, ORM/query builder, template, and
file/URL consumer. Record the accepted type, canonical form, duplicate-key
precedence, charset, and whether validation occurs before or after decoding.

## Differential Families

Test one harmless semantic value at a time using a control and a mutated
request:

- single, double, mixed, and late decoding; Unicode normalization and
  confusables; case and whitespace folding; null/control characters;
- duplicate query/form/JSON keys, parameter pollution, arrays versus scalars,
  nested objects, and order-dependent parsing;
- JSON, form, multipart, XML, text, and observed alternate content types;
- path dot-segments, slash/backslash differences, trailing dots/spaces, and
  framework/router versus filesystem canonicalization;
- client-side-only validation, schema `additionalProperties`, numeric/string
  coercion, and validation performed on one API version but not another.

Do not begin with payloads that execute code, modify data, read secrets, or
consume unbounded resources. Use a fixed marker, a harmless path, or a local
harness until the exact sink and authorization boundary are known.

## Validation

- A bypass exists only when the mutated representation reaches the intended
  sink and causes the concrete security effect that the control prevents.
- A different status, parser error, reflected marker, or accepted extra field
  without security impact is not a finding.
- For WAF-backed targets, load `waf_evasion` and separate edge filtering from
  backend validation; for authenticated actions, preserve principal and CSRF
  context.
- Keep requests bounded, stop on state-changing behavior, and obey rate limits.

Report the control form, mutated form, parser/sink boundary, authenticated
principal, and baseline/proving exchange IDs. If the sink or consequence is
not reachable, record `needs_follow_up` with the exact proof gap.
