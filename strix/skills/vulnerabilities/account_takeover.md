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

## Mailbox-Assisted Test Identity Workflow

When the engagement provides the dedicated `pent6d-gmail-test` mailbox and a
forwarding domain such as `t6d.io.vn`, use it freely for authorized test
identities. Allocate a unique recipient alias per run and role (for example,
`pent6d-user-<run-id>@t6d.io.vn`), then:

1. Register the test identity with that alias; never use a real user's address.
2. Call `mailbox_search` with the exact alias and a `since` timestamp captured
   immediately before the action. Narrow by sender/subject when known.
3. Call `mailbox_read` only for the matching message UID and extract the
   verification link, OTP, recovery token, or invitation required for the
   current flow.
4. Use the value once, keep it out of shared memory and reports, and redact it
   from evidence. Do not read unrelated messages merely because the mailbox is
   a test account.

The mailbox tools are read-only: they cannot send, delete, move, or alter
messages. A missing or expired message is a validation barrier, not permission
to guess an OTP or reuse a token from another alias.

For an explicitly authorized phone-verification flow, load `hupsms` and use
`hupsms_balance`, `hupsms_services`, and one `hupsms_rent` call to obtain a
dedicated test number. Poll the same order with `hupsms_check`, use the OTP
once, and cancel a still-pending order when it is no longer needed. Keep the
provider key, number, OTP, and raw SMS out of shared memory and reports. A
successful rental only proves that the target accepts the delivery channel;
the finding must demonstrate an account-boundary or verification-control
failure.

## Proof Standard

Demonstrate control of a dedicated test account or a harmless account-linking
state. Never target a real user's account, reset token, or session. Record the
exact precondition, identity boundary crossed, and evidence that the prior
owner loses exclusive control.
