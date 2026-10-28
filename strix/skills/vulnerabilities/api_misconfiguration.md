---
name: api-misconfiguration
description: API security testing for inconsistent methods, schema enforcement, object binding, and version-specific controls
---

# API Misconfiguration

API weaknesses often arise where the documented contract, gateway policy, and
application handler disagree. Review each endpoint as a method, media-type,
schema, authorization, and error-handling combination.

## Review Matrix

- Compare documented methods with accepted methods and method-override headers.
- Check that unknown JSON fields, duplicate fields, arrays in place of scalars,
  and null values are rejected consistently.
- Identify privileged or server-owned properties that can be bound from input;
  hand those cases to `mass_assignment`.
- Compare API versions, alternate content types, batch endpoints, and internal
  looking routes; use `shadow_api` when inventory is incomplete.
- Verify error responses do not expose stack traces, schemas, internal hostnames,
  or authorization distinctions beyond the contract.

## Validation

Use an operator-owned object and a minimal request difference. Prove that a
method, field, or parser choice changes an authorization or validation outcome.
An undocumented response field alone is an observation, not a data-exposure
finding, until restricted data is shown to be reachable.
