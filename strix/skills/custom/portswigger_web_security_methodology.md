---
name: portswigger-web-security-methodology
description: Evidence-first routing and test methodology for the complete PortSwigger Web Security Academy web vulnerability taxonomy
---

# Web Security Academy Coverage Methodology

Use this skill after web/API reconnaissance to turn observed technology,
endpoints, identities, browser behaviour, and proxy topology into a focused
vulnerability-test dispatch matrix. It is a coverage and validation framework,
not permission to test every vector blindly. Load the matching specialist skill
before sending payloads or state-changing requests.

## Core Discipline

For every candidate, record:

1. **Signal** — the route, parameter, fingerprint, source location, response
   differential, or business workflow that made the test relevant.
2. **Baseline/control** — a benign or denied request and an allowed request
   using controlled identities where authorization is involved.
3. **One changed condition** — vary one parser, identity, state, protocol, or
   input boundary at a time.
4. **Security consequence** — unauthorized read/write, code execution,
   cross-origin action, cross-user effect, durable business-state violation, or
   an equivalent bounded proof. Scanner labels and server errors are not proof.
5. **Closure** — report, rule out with the enforcing control, or record a
   Thinking/open-proof-gap item with the exact missing prerequisite.

Build a dispatch row in this form:

```text
surface → observed signal → attacker model/prerequisites → specialist skill(s)
        → safe validation oracle → evidence needed → closure owner
```

Do not put a full copy of proxy traffic or a large payload corpus into shared
memory. Save compact facts, capabilities, affected endpoints, role/tenant
boundaries, and completed proof steps with `remember_shared_memory`.

## PortSwigger Topic Routing Matrix

### SQL injection

**Signals:** database errors, filter/sort/search inputs, numeric IDs, login,
report/export filters, GraphQL resolver arguments, unusual timing, or source
that concatenates a query.

**Method:** load `sql_injection`; add `second_order_sqli` when user-controlled
data is stored and later consumed. Establish a benign baseline, then compare
syntax, boolean, error, and bounded time differentials. Confirm the affected
query path and impact with the least invasive proof.

### Cross-site scripting and DOM vulnerabilities

**Signals:** reflection, stored rich text, Markdown, templates, URL fragments,
client-side sinks, `postMessage`, unsafe framework rendering, or weak CSP.

**Method:** load `xss`; add `browser_security` for DOM, context, worker, popup,
or cross-origin behaviour. Identify source → transform → sink and the exact
parser context before selecting any test. Require controlled script execution
or a safe equivalent browser proof; reflection alone is not XSS.

### CSRF, clickjacking, and CORS

**Signals:** cookie-authenticated state changes, permissive framing, OAuth
linking, account settings, payment actions, Origin/CORS headers, or cross-site
browser flows.

**Method:** load `csrf`, `clickjacking`, or `cors_misconfiguration` as
appropriate. Use a controlled origin and controlled account. Prove an action or
read that a cross-site attacker can perform under real browser credential and
user-interaction constraints; do not report headers in isolation.

### XXE, SSRF, and request-side pivots

**Signals:** XML/SOAP/SVG/office uploads, URL fetchers, webhook callbacks,
image/PDF renderers, importers, proxy configuration, or source-side HTTP
clients.

**Method:** load `xxe` or `ssrf`; use a controlled callback/oracle where
authorized. Map redirect handling, DNS/IP parsing, allowlists, and reachable
internal protocol boundaries. If a pivot reaches an internal service, create a
new focused validation task rather than treating reachability alone as final
impact.

### HTTP request smuggling, HTTP/2 desync, and host routing

**Signals:** CDN/WAF/load balancer → origin topology, HTTP/2 downgrade,
connection reuse, inconsistent errors, duplicate header acceptance, or routing
controls at the edge.

**Method:** load `http_request_smuggling`; load `advanced_http_desync` for
browser-powered/client-side desync, CL.0, queue poisoning, or HTTP/2 newline
handling. Capture repeatable timing/differential evidence on controlled
requests first. Escalate only if an edge control, another user's response, a
cache, or an internal route is demonstrably affected. Pair with
`host_header_injection` and `cache_poisoning` where relevant.

### Command injection, SSTI, deserialization, and path traversal

**Signals:** system utilities, image/PDF/media conversion, template rendering,
serialized blobs, file paths, archive extraction, plugin/build tooling, or
source-to-sink traces.

**Method:** load `rce` plus `argument_injection`, `ssti`,
`insecure_deserialization`, or `path_traversal_lfi_rfi` based on the boundary.
Prefer a reversible timing/output/callback oracle. Separate input acceptance,
file placement, parser invocation, and execution: passing an upload filter does
not prove a reachable execution sink.

### Access control, authentication, OAuth, JWT, and API authorization

**Signals:** object IDs, tenant/organization parameters, role-specific UI,
admin endpoints, REST/GraphQL/gRPC/WebSocket variants, tokens, SSO, recovery,
or partially authenticated/MFA-pending sessions.

**Method:** load `idor`, `broken_function_level_authorization`,
`authentication_bypass`, `authentication_jwt`, and the relevant `oauth` or
`saml` protocol skill. Maintain distinct controlled identities and compare
anonymous, peer, privileged, and tenant-separated requests. Test transport and
version parity. A valid token, route existence, or changed status code is not a
bypass without a protected consequence.

### Business logic, race conditions, and exceptional states

**Signals:** checkout/payment/refund, quotas, invitations, approval flows,
reservation, retries, background jobs, webhooks, state transitions, or
idempotency keys.

**Method:** load `business_logic`, `race_conditions`, and
`exceptional_conditions`. Draw the state machine and invariants before sending
parallel requests. Use synthetic data, strict concurrency ceilings, and
before/after evidence from an authoritative endpoint or ledger. Test replay,
out-of-order, partial-failure, time-boundary, and cross-channel variants.

### WebSocket, GraphQL, API, and NoSQL

**Signals:** upgrade endpoints, Socket.IO polling, subscriptions, GraphQL
schemas, batch operations, REST OpenAPI specs, resolver errors, document-store
filters, or mobile-client API calls.

**Method:** load `websocket`, `graphql`, `api_misconfiguration`, and/or
`nosql_injection`. Test authorization per message/resolver/operation rather
than only at the HTTP handshake. Compare REST, GraphQL, gRPC and socket paths
for the same protected object/action. Bound batching and query depth tests to
avoid availability impact.

### Web cache poisoning and cache deception

**Signals:** CDN/cache headers, static extensions, path normalization,
authenticated dynamic GETs, `Vary`, forwarded headers, reflected host/URL
inputs, or differing origin/cache parsing.

**Method:** load `cache_poisoning`. Use a per-request cache buster and a
harmless marker. First prove cacheability and the cache key; then test one
unkeyed input or parser differential at a time. Validate from an independent
clean request/profile. Treat persistent victim-oriented poisoning and cache
eviction as out of bounds unless explicitly authorized.

### Information disclosure, uploads, prototype pollution, and browser features

**Signals:** stack traces, source maps, backups, debug endpoints, uploads,
archive handling, deep merge utilities, JSON/YAML import, service workers,
postMessage, or client-side routing.

**Method:** load `information_disclosure`, `source_artifact_leakage`,
`insecure_file_uploads`, `prototype_pollution`, and/or `browser_security`.
Separate metadata exposure from non-public impact. For source artifacts,
validate that recovered code serves the in-scope target before deriving or
testing code candidates.

### Web LLM attacks

**Signals:** chat, RAG, agents, tool calls, remote content ingestion, memory,
file uploads, model connectors, or automated actions.

**Method:** load `llm_applications` and `llm_prompt_injection`. Model the
effective authority of tools and retrieved content. Prove an unauthorized tool
action, cross-tenant retrieval, data boundary crossing, or durable policy
bypass — an amusing model response alone is not a reportable issue.

## Topics That Need Explicit Dispatch

The following Academy-style topics are easy to miss because reconnaissance
does not always label them as vulnerabilities. Trigger a specialist when the
signal appears:

| Observed signal | Required specialist routing |
|---|---|
| CDN/cache/proxy/cache headers | `cache_poisoning` + `http_request_smuggling` when a multi-hop proxy exists |
| API schema, mobile client, GraphQL, gRPC | `api_misconfiguration` + protocol skill + `idor`/`broken_function_level_authorization` |
| Login/SSO/recovery/MFA | `authentication_bypass` + JWT/OAuth/SAML/MFA/session skills |
| Stateful workflow/payment/quota | `business_logic` + `race_conditions` |
| Upload/conversion/import/archive | `insecure_file_uploads` + `path_traversal_lfi_rfi` + `rce` as evidence dictates |
| Browser workers/popups/messages/cross-origin flow | `browser_security` + the primary vulnerability skill |
| Product/version/framework fingerprint | matching framework/technology skill + `cve_exploit_validation` |

## Completeness Review

Before completion, root must ask:

1. Which Academy topic families are applicable to the observed architecture?
2. Which received a specialist dispatch, and which were explicitly
   not-applicable with evidence?
3. Did every protected operation receive identity/tenant/transport parity
   testing where suitable?
4. Did cache/proxy/browser signals receive differential testing rather than a
   header-only review?
5. Did every candidate end as confirmed, ruled out, informational, or Thinking
   with a concrete proof gap?

Use the coverage ledger to preserve these answers. This is how broad Academy
knowledge becomes auditable test coverage rather than a list of remembered bug
names.
