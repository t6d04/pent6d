---
name: authentication_bypass
description: Evidence-first testing of local, session, gateway, and alternate-route authentication bypasses
---

# Authentication Bypass

Use this skill when reconnaissance finds a login, session, API gateway, basic
authentication, impersonation, or alternate authentication path. The goal is
to prove an unauthenticated or lower-privileged principal can cross an
authentication boundary it should not cross. Load `authentication_jwt`,
`mfa_bypass`, `session_management`, `forgot_password`, `oauth`, or `saml` for
the protocol-specific parts instead of duplicating their rules.

## Scope and Principals

- Confirm the target, protected action, expected principal, and authorized
  test accounts before sending mutations.
- Build a matrix of unauthenticated, low-privilege, peer-user, and admin/test
  principals. Keep cookies, tokens, CSRF state, and account identifiers
  separate per principal.
- Test the same action through every observed route, API version, HTTP method,
  gateway/backend hop, WebSocket message, and mobile/deep-link entry point.

## Bypass Families

### Login and Partial Authentication

- Distinguish a pre-auth, password-verified, MFA-pending, and fully-authenticated
  session; test whether a pending session reaches protected routes or receives
  privileged tokens.
- Compare failure, redirect, method, content-type, and duplicate-parameter
  handling without guessing passwords or spraying credentials.
- Check account-recovery, invitation, magic-link, device-trust, and remember-me
  paths for issuance of a stronger session than the verified proof permits.

### Session, Headers, and Gateways

- Verify rotation and binding when privilege changes, login completes, logout
  occurs, or a session is resumed on another device.
- Compare edge and origin behavior only through in-scope routes. Treat
  `X-Forwarded-*`, `X-Original-URL`, user/role headers, host routing, and
  gateway-added identity as candidates only when the application actually
  consumes them; do not invent trusted headers.
- Test versioned and undocumented routes for missing middleware, method
  override, OPTIONS/HEAD differences, and inconsistent auth between REST,
  GraphQL, WebSocket, and RPC transports.

### Token and Federation Boundaries

Delegate JWT claim/signature, OAuth/OIDC, SAML, and MFA checks to their
specialist skills, then validate the resulting token/session against the
intended audience, issuer, client, tenant, and privilege. A token that is
valid but accepted by the wrong service is an authentication-boundary bypass.

## Safe Validation

1. Capture a denied baseline and an allowed control with the same route and
   test account context.
2. Change one boundary condition at a time: session state, route/version,
   method, content type, or explicitly observed gateway input.
3. Require a protected response or state change belonging to the wrong
   principal. A different error page, route existence, or successful logout is
   not proof of bypass.
4. Stop after a minimal proof; do not access real user data, alter roles,
   change passwords, create persistence, or enumerate accounts at scale.

### Email Verification and Signup

For an explicitly authorized registration flow, use the dedicated test mailbox
profile to complete email verification. Generate a unique alias under the
engagement's forwarding domain, record the action timestamp, then use
`mailbox_search` and `mailbox_read` to retrieve only the matching verification
message or OTP. Keep the mailbox session separate from the target's user
session and never reuse a link/code across aliases or runs. After the account
is verified, continue with the lowest-privilege test principal and compare the
same protected action against anonymous and authenticated baselines.

If the target requires SMS verification, load `hupsms` and use one bounded
temporary-number rental for the dedicated test identity. Poll the matching
order with `hupsms_check`, submit the returned OTP once, and do not treat
provider delivery as proof of bypass. Check account/session/action binding,
replay protection, expiry, and alternate verification paths while keeping raw
phone and OTP values out of evidence.

## Reporting

Record the exact principal transition, route, preconditions, baseline/control,
and proving exchange IDs. File a report only when the protected consequence is
replayable. Record a CVE/auth candidate as `needs_follow_up` when credentials,
tenant context, or a safe proof is missing; never call uncertainty a bypass.
