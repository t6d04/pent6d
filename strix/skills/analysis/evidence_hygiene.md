---
name: evidence-hygiene
description: Safe handling, redaction, and reproducible capture of HTTP and source evidence for security findings
---

# Evidence Hygiene

Evidence must make a finding reproducible without expanding the disclosure of
secrets, personal data, or unrelated target information.

## Before Saving or Reporting

- Keep the minimum request and response needed to prove the issue.
- Reference captured proxy exchanges by ID instead of copying full raw
  headers or bodies into notes and reports.
- Redact session cookies, bearer tokens, API keys, passwords, private keys,
  recovery codes, and one-time links. Never place them in a task, todo, or
  finding narrative.
- Mask unnecessary PII. Show only the smallest data fragment needed to
  establish unauthorized access or impact.
- State whether test accounts, synthetic records, or operator-owned data were
  used. Prefer them whenever the engagement permits.

## Dynamic Evidence

Capture a benign control request and a proving request with the same method,
target, and authentication context. Record the request IDs, timing window if
relevant, and the observable difference. Do not claim an HTTP exchange exists
if it was not captured by the proxy.

## Files and Screenshots

Use stable names that identify the finding and step, not a secret or victim.
Before attaching output, check filenames, query strings, cookies, page text,
and metadata for sensitive values. Remove bulky raw artifacts once their
minimal, redacted evidence has been recorded.

## Reporting Boundary

The report explains the security impact; it is not a data-exfiltration record.
For a confirmed issue, use a harmless marker, a test record, or a redacted
sample. If that is insufficient to prove impact, record the exact reason and
escalate through the engagement's evidence-handling process.
