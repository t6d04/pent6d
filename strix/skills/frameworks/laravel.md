---
name: laravel
description: Laravel security review for routes, middleware, signed URLs, queues, storage, and operational dashboards
---

# Laravel

## Surface

- Route groups, middleware, policies/gates, API resources, validation rules,
  mass assignment configuration, and exception handling.
- Signed URLs, password reset, queues, jobs, broadcasts, storage disks, and
  direct-to-cloud upload flows.
- Operational components such as debug mode, logs, Telescope, Horizon, and
  package configuration.

## Review Method

Map each public route to its middleware and policy, then compare web and API
routes for inconsistent protection. Treat debug output, dashboards, and known
framework advisories as candidates: verify exact version, configuration,
reachability, and impact before reporting. Pair raw query construction with
`sql_injection`, and object binding with `mass_assignment` or `idor`.
