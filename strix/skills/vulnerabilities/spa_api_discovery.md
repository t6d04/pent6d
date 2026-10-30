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
does not expand the run's declared target list. Record provenance and keep
active requests within the original target boundary.
