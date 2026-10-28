---
name: forgot-password
description: Password-recovery and account-recovery workflow security testing
---

# Password Recovery Security

Recovery flows frequently cross trust boundaries between unauthenticated
requests, email delivery, browser state, support operations, and an existing
session.

## Map the Lifecycle

Request reset → verify recipient → issue token/link/code → verify token → set
password → revoke old sessions. Also map email-change, account-linking, and
MFA-recovery variants.

## Review

- Token binding to account, purpose, expiry, use count, and security-state
  changes.
- Host and URL construction for reset links; pair with `host_header_injection`.
- Enumeration differences, but report them separately from account takeover.
- Whether a successful reset revokes old sessions and recovery artifacts.
- Rate limits and anti-automation behavior without performing credential
  guessing against non-test accounts.

## Validation

Use only accounts and inboxes controlled by the engagement. Prove a concrete
recovery-boundary failure, not merely that a token format looks predictable.
