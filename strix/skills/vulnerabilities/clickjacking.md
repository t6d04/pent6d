---
name: clickjacking
description: UI-redressing analysis for sensitive browser actions and framing protections
---

# Clickjacking

Missing framing protection becomes a vulnerability only when an attacker can
induce a meaningful, authenticated state change or disclosure through an
embedded page.

## Review

- `Content-Security-Policy: frame-ancestors` and legacy frame options across
  login, account, payment, admin, consent, and OAuth endpoints.
- Frame-busting behavior, nested frames, and differences between primary and
  legacy hosts.
- Whether the target uses browser defenses that prevent cookies or sensitive
  actions from working in a cross-site frame.

## Proof

Use a local harmless framing page and an operator-owned account. Demonstrate a
specific action, not simply that the page renders in an iframe. If the endpoint
is read-only or cookies are withheld, document it as defense-in-depth only.
