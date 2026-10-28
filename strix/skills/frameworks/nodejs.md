---
name: nodejs
description: Node.js and Express security review for middleware, parsers, proxy trust, async boundaries, and package use
---

# Node.js and Express

## Surface

- Express/Fastify/Nest middleware order, route matching, error handlers,
  body parsers, template engines, static serving, and WebSocket upgrades.
- Proxy trust, forwarded headers, rate limiting, CORS, session stores, and
  async job/event handlers.
- Dynamic object merge, path construction, command argument assembly, raw
  database access, and package lockfiles.

## Review Method

Trace user input through parser and middleware boundaries to its consumer.
Use focused skills for the sink: `prototype_pollution`, `argument_injection`,
`path_traversal_lfi_rfi`, `ssti`, `sql_injection`, or `websocket`. For package
advisories, use `dependency_cve_scanning` and prove the installed version and
reachable feature.
