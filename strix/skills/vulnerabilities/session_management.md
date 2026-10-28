---
name: session-management
description: Session lifecycle, rotation, revocation, cookie, and device-trust security testing
---

# Session Management

Map the complete session lifecycle: anonymous state, login, privilege change,
password/email/MFA change, logout, idle expiry, absolute expiry, and recovery.

## Check

- Session identifier rotation at login and privilege elevation.
- Revocation after logout, password reset, factor change, account disable, and
  suspicious-device events.
- Cookie scope, Secure/HttpOnly/SameSite attributes, token storage, and
  competing sessions across browser and API clients.
- Device-trust and remember-me artifacts bound to the correct user and device.

## Proof

Use controlled accounts and a captured before/after session. Demonstrate that
the old artifact remains accepted after a security event, or that one account's
artifact is accepted for another. Do not retain or disclose live session
secrets; reference proxy evidence by ID.
