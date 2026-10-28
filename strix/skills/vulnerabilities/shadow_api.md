---
name: shadow-api
description: Discovery and validation of undocumented, legacy, debug, and client-inferred API surfaces
---

# Shadow API Discovery

A shadow API is a reachable interface absent from the documented contract or
protected differently from the primary API. It can arise from legacy routes,
version migrations, mobile clients, debug endpoints, generated SDKs, feature
flags, or service-to-service paths exposed at the edge.

## Discovery Sources

- JavaScript bundles, source maps, mobile clients, generated SDKs, GraphQL
  schemas, OpenAPI drift, route manifests, and proxy history.
- Deprecated version prefixes, alternate content types, uncommon HTTP methods,
  error messages, CORS preflight responses, and documentation examples.
- White-box route registrations, reverse-proxy rules, feature flags, and test
  fixtures compared with published API documentation.

## Triage

For every candidate route, record the source, path, method, authentication
expectation, data class, and whether it falls within authorized scope. Do not
turn a hostname or URL inferred from code into an active target without scope
approval.

## Validation

Compare the hidden route with its supported counterpart using authorized test
identities. Look for missing authentication, missing object authorization,
unexpected data fields, permissive CORS, inconsistent rate limits, or a
different validation path. A 404 or generic error is not proof that a route is
absent; distinguish proxy, gateway, and application responses.

## Handoff

Feed confirmed routes and their auth model into the threat model, then assign
only the relevant specialist: `idor`, `mass_assignment`, `authentication_jwt`,
`sql_injection`, or another narrow skill. Record routes that remain unproven as
coverage gaps rather than treating them as findings.
