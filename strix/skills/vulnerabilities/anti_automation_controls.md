---
name: anti-automation-controls
description: Server-side rate limiting, CAPTCHA, OTP, replay, and enumeration-resistance testing for authentication workflows
---

# Anti-Automation Controls

Login, registration, recovery, invitation, OTP, and verification flows require
server-side controls that survive retries, alternate clients, and distributed
request paths.

## Review

- Rate-limit keys: account, IP, device, tenant, challenge, and endpoint.
- CAPTCHA verification, token binding, expiry, single use, and server-side
  enforcement rather than client-side field presence.
- OTP/code length, expiry, replay protection, attempt budgets, and reset after
  security-state changes.
- User enumeration through status, body, timing, redirects, or asynchronous
  delivery behavior.

## Safe Validation

Use test accounts and a low, pre-agreed attempt budget. Show that the server
accepts a reused or omitted proof, or that a rate limit can be bypassed without
performing password guessing or exhausting a real user's account. Record the
server-side decision point and recovery behavior after failure.

When signup or recovery sends an email to the dedicated forwarding domain,
retrieve the message with `mailbox_search`/`mailbox_read` using the exact test
alias and a narrow time window. Do not scan unrelated mailbox content or use
the mailbox to bypass a control for a real account.

For an authorized SMS/phone flow, load `hupsms` and use one rented test number
with a small, pre-agreed attempt budget. Poll the same order rather than
requesting new numbers repeatedly. Measure server-side rate-limit keys,
challenge binding, expiry, replay, and attempt counters; provider errors or
successful OTP delivery alone are not findings.
