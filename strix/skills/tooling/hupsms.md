---
name: hupsms
description: Bounded HupSMS temporary-number and OTP workflow for authorized signup and authentication testing
---

# HupSMS Temporary Phone Workflow

Use this skill only when the engagement explicitly authorizes creating test
accounts or verifying a phone-based signup/authentication flow. The connector
is available to worker agents through these tools:

- `hupsms_balance`
- `hupsms_services`
- `hupsms_rent`
- `hupsms_check`
- `hupsms_cancel`
- `hupsms_rerent`

For TOTP enrollment, worker agents also have the run-scoped tools
`mfa_secret_store`, `mfa_secret_status`, and `mfa_totp_code`.

## Configuration

The host process reads `PENT6D_HUPSMS_API_KEY` from the environment or the
gitignored `.env.hupsms.local` file. Never ask the model to repeat the API key,
place it in a prompt, write it to shared memory, or include it in a finding.
The optional `PENT6D_HUPSMS_BASE_URL` is intended for an approved provider or
test stub and defaults to `https://hupsms.com/api/v1`.

## Required sequence

1. Confirm scope and that the target's phone-registration or OTP flow is an
   explicitly authorized test case.
2. Call `hupsms_balance`, then `hupsms_services` to choose the exact service
   and record the provider's price/timeout.
3. Call `hupsms_rent` with the service id. Use `network` or `prefix` only when
   the target requires a specific carrier or prefix.
4. Submit the returned phone number to the current test flow. Use a unique
   test identity per run and do not use a real person's number.
5. Call `hupsms_check` for the same `orderId` until `data.status` is terminal:
   `success`, `cancelled`, or `expired`. Respect the provider timeout and do
   not poll aggressively; back off between checks.
6. If `data.status=success`, use the returned OTP/SMS content exactly once in
   the current flow. Do not put the OTP, full SMS, or phone number in shared
   memory or reports; retain only redacted evidence such as the state
   transition and timestamp.
7. If the order is still pending and no longer needed, call `hupsms_cancel`.
   Cancellation/refund is server-specific and is not possible after OTP
   delivery. Use `hupsms_rerent` only when the test explicitly needs the same
   number again and the provider allows it.

## Flow-specific playbooks

### Signup and phone verification

- Establish an authorized test identity and capture the pre-registration
  timestamp before renting a number.
- Use the returned number only in the current target flow. Do not share one
  number between parallel runs, roles, tenants, or unrelated targets.
- Verify that the server, rather than only the UI, binds the OTP to the number,
  account, session, tenant, and intended operation. Compare the unverified and
  verified states with the same low-privilege test account.
- Check whether the account becomes usable before verification, whether a
  verification token can be replayed, and whether changing the phone number
  invalidates prior challenges. Stop after a minimal proof.

### Sign-in and recovery

- Prefer an already-created, lowest-privilege test account. Renting a number
  does not authorize account enumeration or password-reset testing against
  other users.
- For login-by-phone, compare known-test-account and non-existent-account
  responses for status, body, timing, and delivery behavior without spraying
  identifiers or OTPs.
- For recovery, trigger the flow only for the test account, retrieve the
  matching SMS, and verify expiry, single-use, account binding, session
  binding, and behavior after a password or phone change.
- Never use an OTP from a different order, run, alias, tenant, or account as a
  fallback when the expected message is missing.

### MFA, step-up, and phone changes

- Use a test account with a known password and a dedicated rented number. Test
  the states before password verification, after password verification, while
  MFA is pending, and after MFA completion.
- Exercise only the protected action that is in scope, such as a profile,
  password, payment, role, API-key, or phone-number change. Confirm the server
  enforces the challenge on equivalent API routes and methods.
- For add/change/remove-phone flows, check re-authentication, confirmation of
  the old factor, new-factor verification, notification, recovery fallback,
  and revocation of old sessions. Do not permanently weaken or remove a real
  user's factor.

When the target offers TOTP enrollment, always preserve the test factor before
leaving the enrollment page:

1. Capture the displayed `otpauth://totp/...` URI or base32 secret and call
   `mfa_secret_store` with a unique label. If a QR code is shown, capture a
   PNG/JPEG screenshot and pass its absolute path as `qr_image_path`.
2. Call `mfa_secret_status` and require both `secret_stored=true` and
   `qr_image_stored=true` when a QR image was available. The files are kept
   under the current run's private state directory, not shared memory.
3. For later login or protected-action tests, call `mfa_totp_code` with the
   same label immediately before submitting the challenge. Never copy the
   secret or generated code into a report, message, or shared memory.
4. If enrollment exposes only a QR image, use an approved local decoder to
   recover the `otpauth` URI, then store both the decoded secret and original
   image. If decoding fails, mark the MFA workflow blocked instead of guessing.

If the factor is SMS, use the `hupsms` flow and retain the order state rather
than a permanent secret. If it is WebAuthn/security-key based, do not attempt
to export or clone the private key; use the approved test authenticator and
record only redacted state transitions.

## Result handling

Treat these as operational states rather than vulnerabilities:

| Result | Agent action |
| --- | --- |
| `data.status=pending` | Back off and poll the same order until timeout. |
| `data.status=success` | Use the OTP/SMS once, then continue the current flow. |
| `data.status=expired` | Stop; do not guess or reuse the code. |
| `data.status=cancelled` | Stop; rent a new number only if the test still needs one. |
| `NO_NUMBER_AVAILABLE` or `RATE_LIMIT` | Record the blocker and respect the provider limit. |
| Missing API key or invalid service | Mark the phone test blocked; do not improvise another provider. |

When recording evidence, keep only redacted metadata such as order state,
timestamp, target route, account role, and whether the verification gate held.
Never copy the raw phone number, OTP, SMS body, provider key, or audio URL into
shared memory, agent messages, or findings.

## Validation and safety gates

- A successful OTP retrieval proves delivery, not a vulnerability. Report a
  finding only when the target's authorization, verification, MFA, replay,
  rate-limit, or account-binding control is demonstrably broken.
- Use the minimum number of rentals and OTP attempts. Never spray OTPs, create
  bulk accounts, bypass a target's anti-abuse controls, or test real users.
- Treat `pending`, `NO_NUMBER_AVAILABLE`, `RATE_LIMIT`, and provider failures
  as operational results, not security findings. Retry only with bounded
  backoff and stop at the documented expiration.
- Keep HupSMS credentials and raw OTP/SMS data out of reports, shared memory,
  agent messages, and long-lived artifacts.
