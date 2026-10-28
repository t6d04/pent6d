---
name: spa-api-discovery
description: Single-page application bundle analysis for backend API inventory and authorization-boundary testing
---

# SPA API Discovery

Modern browser bundles often contain the most complete public inventory of
backend routes, GraphQL operations, feature flags, API versions, and client
authorization assumptions.

## Method

1. Collect scripts, manifests, source maps, generated clients, and runtime
   configuration from the authorized application.
2. Extract routes, methods, parameters, operation names, hosts, and version
   prefixes; distinguish static strings from verified reachable endpoints.
3. Compare the bundle inventory with documented APIs and proxy history.
4. Send confirmed in-scope routes to `shadow_api`, `idor`, `mass_assignment`,
   `graphql`, or other focused skills.

## Boundaries

An endpoint string, third-party hostname, or stale deployment URL in a bundle
is not authorization to test it. Record provenance and use `scope_triage`
before active requests outside the original target boundary.
