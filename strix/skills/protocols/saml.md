---
name: saml
description: SAML federation, assertion validation, relay state, and identity-mapping security testing
---

# SAML Security

Treat SAML as a chain of issuer trust, assertion validation, audience and
recipient binding, signature handling, relay state, and local account mapping.

## Review

- Exact issuer, audience, ACS URL, destination, time window, and signature
  requirements.
- Whether the service validates the signed element it consumes and rejects
  duplicate/conflicting identifiers.
- RelayState and return URLs, IdP-initiated versus SP-initiated flows, and
  account linking by email/name identifier.
- Certificate rollover, metadata refresh, and tenant/organization mapping.

## Validation

Use test IdP and SP accounts. Demonstrate an assertion or mapping accepted
outside its intended binding; configuration observations alone are not a login
bypass. Do not replay production assertions or alter federation metadata.
