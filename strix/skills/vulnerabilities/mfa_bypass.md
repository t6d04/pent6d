---
name: mfa-bypass
description: Multi-factor authentication workflow, enrollment, recovery, and step-up authorization analysis
---

# Multi-Factor Authentication Security

MFA controls are secure only when the server binds a successful challenge to
the intended account, session, action, and expiry, and enforces it on every
privileged path.

## Review Areas

- Login, enrollment, factor replacement, remembered-device, backup-code, and
  recovery workflows.
- Step-up checks before sensitive actions such as password change, payment,
  key generation, or role administration.
- Challenge replay, cross-account binding, partial-login sessions, and race
  conditions between verification and token issuance.
- Server-side verification of CAPTCHA and rate-limit state; do not treat a
  client-side widget as an enforcement point.

## Validation

Use only test factors and accounts. Prove that a protected action succeeds
without a valid, correctly bound factor; an unavailable factor provider or a
different UI flow is not a bypass. Keep attempts within the engagement's
authentication-rate limit.

## Bypass Matrix

Test the same protected action across the states `pre-authenticated`,
`password-verified`, `MFA-pending`, `MFA-complete`, remembered-device, and
recovery. Cover the factor types actually exposed by the target (TOTP, SMS,
email OTP, push, WebAuthn/security key, backup code) without enrolling or
resetting factors on real users.

- Verify challenge binding to account, session, device, action, tenant, and
  expiry; compare a challenge from account A against account B and a different
  privileged action.
- Check replay, omission, duplicate verification, parallel verification,
  fallback-factor downgrade, recovery-link reuse, and token issuance before
  completion.
- Confirm step-up is enforced server-side on every equivalent API, method,
  version, WebSocket/RPC path, and password/email/role/payment/key change.
- Keep OTP attempts and recovery checks to the agreed test budget; never spray,
  lock out a real account, weaken a production factor, or retain test factors
  after the run.

For an explicitly authorized SMS-MFA test identity, load `hupsms`, rent one
number, and poll its order with `hupsms_check`. Use the OTP only once to
exercise the current challenge. Do not use the connector to create bulk
accounts or bypass provider/target rate limits; preserve only redacted state
transitions and timestamps.

For TOTP enrollment on a dedicated test account, preserve both forms of the
factor before testing login: capture the text `otpauth`/base32 secret and the
QR screenshot, then call `mfa_secret_store` with a run-unique label. Verify
with `mfa_secret_status`; generate a fresh code for each login or step-up with
`mfa_totp_code`. Never put the seed, QR image, or generated code in shared
memory, agent messages, findings, or screenshots that leave the private run
directory. Rotate/revoke the factor after testing when the target supports it.

A valid MFA finding requires a protected consequence attributable to the
missing or misbound factor, with denied and successful controls recorded.
