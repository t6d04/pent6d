---
name: account-takeover
description: Account takeover analysis across registration, recovery, federation, sessions, and identity-linking workflows
---

# Account Takeover

Treat account takeover as an end-to-end identity lifecycle problem, not a
single login defect. Map enrollment, email change, recovery, SSO linking,
device trust, and session revocation for an operator-owned test account.

## Candidate Paths

- Recovery tokens exposed, reusable, insufficiently bound, or accepted after
  password/email/MFA changes.
- Account linking that trusts an unverified email, issuer, tenant, or callback.
- Invitation, magic-link, change-email, and support-assisted recovery flows
  whose state can be confused across accounts.
- Sessions surviving a security-sensitive transition; load `session_management`.
- Weak anti-automation or MFA controls; load `mfa_bypass` only when the
  engagement permits authentication-flow testing.

## Proof Standard

Demonstrate control of a dedicated test account or a harmless account-linking
state. Never target a real user's account, reset token, or session. Record the
exact precondition, identity boundary crossed, and evidence that the prior
owner loses exclusive control.
