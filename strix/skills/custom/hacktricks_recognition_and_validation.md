---
name: hacktricks-recognition-and-validation
description: Environment-aware recognition signals, pivot hypotheses, and evidence-first validation routes for web, identity, infrastructure, cloud, and CI/CD assessments
---

# HackTricks Recognition and Validation Overlay

Use this skill after reconnaissance when the target exposes implementation,
identity, infrastructure, cloud, or integration signals that a web-only
checklist might miss. It complements the PortSwigger methodology: PortSwigger
organizes web vulnerability families; this overlay turns environmental clues
into a bounded, in-scope test hypothesis and routes it to the narrowest
specialist skill.

This is a recognition and validation playbook, not a payload catalogue. Keep
testing proportional, preserve request/evidence IDs, and do not use a clue to
expand beyond the authorized target or access level.

## The Five-Step Route

For every signal, work through the same sequence:

1. **Signal** — record the exact observed header, route, source reference,
   banner, response difference, repository file, or identity claim.
2. **Capability** — state the attacker-controlled value, identity, protocol,
   or boundary that might make the signal security-relevant.
3. **Differential** — make the smallest safe comparison against a baseline:
   another authorized role, object, content type, method, representation, or
   controlled callback.
4. **Pivot** — if the differential is meaningful, dispatch the matching
   specialist with the concrete asset and proof goal. Do not turn a product
   name or status-code change into a finding.
5. **Closure** — classify the route as confirmed, ruled out, informational
   (specific validation gap), or needs-follow-up (missing prerequisite). Save
   reusable facts and relationships in shared memory, not whole raw responses.

## Recognition Families and Safe Test Routes

### Surface, Stack, and Artifact Clues

Treat framework headers, error class names, versioned static assets, public
source maps, API specifications, JavaScript route lists, backup naming,
container manifests, service banners, and administrative paths as **routing
evidence**. First establish whether the item is current and tied to the target;
then map the exposed route, feature, version, and authentication state.

- Public `.git`, archives, source maps, build manifests, or exposed code:
  use `source_artifact_leakage`, then validate that code/configuration belongs
  to the active target before using `local_code` or source-aware review.
- Swagger/OpenAPI, GraphQL schema, gRPC reflection, mobile APIs, legacy
  versions, or JavaScript-only routes: use `shadow_api`, `spa_api_discovery`,
  and the appropriate protocol skill before authorization testing.
- Exact product/plugin/version evidence: use the matching framework skill,
  `default_credentials` only for documented bootstrap credentials, and
  `cve_exploit_validation` for bounded CVE closure.

### Identity, Authentication, and Tenant Signals

Login, invitation, recovery, impersonation, SSO, MFA, device-trust, role,
organization, and account-linking flows are state machines. Build an
authorized account/tenant/role matrix before changing one variable at a time.

Look for mismatches between UI and API authorization, claims and server-side
roles, tenant identifiers in paths/body/headers, session state after logout or
role changes, alternate API hosts, and recovery channels that bypass a primary
control. Route to `authentication_bypass`, `session_management`,
`authentication_jwt`, `mfa_bypass`, `forgot_password`, `account_takeover`,
`oauth`, or `saml` as indicated. A changed error, token shape, or accepted
request is not proof without an unauthorized protected consequence.

### API, Object, and Protocol Boundaries

Versioned paths, undocumented verbs, bulk endpoints, nested object fields,
GraphQL mutations, gRPC methods, WebSocket/Socket.IO events, and asynchronous
webhooks often reveal a second policy enforcement point.

Compare the same authorized operation across roles and tenants; vary one
object reference, field, method, or representation at a time. For a likely
object or function authorization gap use `idor` and
`broken_function_level_authorization`; for client-controlled properties use
`mass_assignment`; for protocol-specific behavior use `graphql`, `grpc`, or
`websocket`. Preserve the baseline and proof requests so an apparent route
difference cannot be mistaken for a security impact.

### Input, Parser, and Representation Mismatches

High-value signals include reflected/stored input, database or directory
errors, template markers, shell/tool integrations, serialized blobs, XML
handlers, duplicate parameters, content-type fallbacks, Unicode/URL decoding,
or disagreements between gateway and origin parsing.

Establish the expected parser and sink first, then compare a harmless control
input with a minimally changed representation. Dispatch only to a relevant
specialist: `sql_injection`, `second_order_sqli`, `nosql_injection`,
`ldap_xpath_injection`, `xss`, `ssti`, `rce`, `argument_injection`,
`insecure_deserialization`, `xxe`, `input_filter_bypass`, or
`http_request_smuggling` / `advanced_http_desync`. Require a repeatable
oracle or demonstrable security consequence; stack traces and generic 500s
are reconnaissance data, not findings.

### Files, Paths, and Content Processing

Uploads, export/import features, document/image conversion, archive handling,
download endpoints, source references, and file metadata create multiple
boundaries: name, MIME, magic bytes, storage location, parser, and later
consumer. Test the workflow end-to-end with benign fixtures and an authorized
account.

Route upload or processing behavior to `insecure_file_uploads`; user-derived
paths or file references to `path_traversal_lfi_rfi`; source/repository
artifacts to `source_artifact_leakage`; and XML/content-parser behavior to
`xxe`. For a disclosed source tree, first validate which deployment uses it;
if it is outside scope, document the exposure and target mapping without
testing a different asset.

### Server-Side Fetching, Proxies, and Internal Reachability

URL previews, import-by-URL, webhook testers, PDF/image renderers, feed
readers, redirectors, proxy features, XML external references, and cloud
metadata-like errors are SSRF/XXE routing clues. Determine the exact parser,
redirect policy, DNS behavior, protocol allowlist, and execution context using
a controlled callback or a harmless, scope-approved endpoint.

Use `ssrf` or `xxe`; only extend toward an internal resource after proving the
server-side fetch boundary and confirming the internal destination is within
authorization. Never use this path for persistence, credential extraction,
lateral movement, or data collection beyond the minimum proof.

### Cache, CDN, Gateway, and WAF Layers

Cache status/age headers, inconsistent `Vary`, reflected host/forwarded
headers, URL normalization differences, stale authorization responses,
HTTP/2-to-HTTP/1 translation, CDN error pages, and challenge pages indicate a
multi-hop request path. Build a cache or parser oracle before testing an
impactful variant.

Route to `cache_poisoning`, `host_header_injection`,
`http_request_smuggling`, `advanced_http_desync`, `waf_evasion`, and
`input_filter_bypass` as appropriate. Test in isolation with unique markers,
bounded timing, and no shared-user impact; a block-page difference is not a
bypass until a protected origin behavior is demonstrated.

### Business Workflows and Concurrency

Prices, quotas, invitations, approvals, inventory, payments, password reset,
webhooks, retries, idempotency keys, and asynchronous jobs expose invariants
that UI-only testing hides. Diagram state transitions and identify who can
perform each transition.

Use an authorized test account and reversible fixtures to compare ordinary and
edge transitions. Route to `business_logic`, `race_conditions`,
`exceptional_conditions`, or `semantic_confusion`. A timing anomaly becomes a
finding only if it violates a durable security or business invariant.

### Browser and Realtime Clients

`postMessage`, embedded frames, cross-origin storage, service workers,
redirect callbacks, CORS headers, client-side route guards, WebSocket events,
and token handling in JavaScript are client/server trust boundaries.

Use `browser_security`, `cors_misconfiguration`, `clickjacking`, `xss`, and
`websocket`. Compare origins, frame ancestors, message senders, user state,
and server-side enforcement. Do not conclude from front-end code alone: prove
the receiving context or server accepts attacker-controlled state.

### Environment, Cloud, CI/CD, and Directory Services

Only enter this branch when the authorized scope or source/recon evidence
names the asset. Signals include cloud hostname patterns, metadata references,
service-account/managed-identity configuration, IaC, Kubernetes manifests,
registry URLs, CI workflow files, secret references, directory/LDAP settings,
VPN/SMB/WinRM/Kerberos services, or explicit enterprise SSO integration.

Route to `aws`, `azure`, `gcp`, `kubernetes`, `ci_cd_security`,
`active_directory`, and related framework skills. Validate identity/role,
policy, and reachable resource relationships from least privilege outward.
Do not enumerate unrelated subscriptions, projects, tenants, networks, or
directory users; do not harvest secrets or move laterally. Record a minimally
sufficient, redacted proof of the misconfiguration instead.

## Routing Table

| Observed signal | Primary skill(s) | Required proof goal |
|---|---|---|
| Source map, archive, exposed repository metadata | `source_artifact_leakage` | Artifact is current and exposes sensitive or actionable content |
| API schema, hidden route, legacy/mobile endpoint | `shadow_api`, `spa_api_discovery` | Endpoint is reachable and policy differs from intended surface |
| Object ID or tenant ID accepted from client | `idor`, `broken_function_level_authorization` | Cross-object/role access to protected action or data |
| User-controlled role/property in request | `mass_assignment` | Server persists an unauthorized sensitive property |
| Login/SSO/MFA/recovery state transition | auth/MFA/OAuth/SAML skills | Protected session/account action occurs without required control |
| Product and exact version/plugin | framework + `cve_exploit_validation` | Version, configuration, and bounded vulnerable condition align |
| Default admin/bootstrap screen | `default_credentials` | Documented credential works and grants a protected capability |
| Parser error, reflection, serialized/XML input | sink-specific injection skill | Reproducible oracle and security-relevant sink behavior |
| URL importer, webhook, renderer, redirect fetch | `ssrf`, `xxe` | Controlled evidence of server-side fetch under allowed scope |
| Upload, conversion, archive, file path | upload/path/source skills | Unsafe later processing, path access, or executable impact |
| Cache/CDN/WAF/forwarded-header difference | cache/desync/WAF skills | Isolated, repeatable effect at protected origin/shared response |
| Workflow, quota, payment, or retry race | `business_logic`, `race_conditions` | Durable invariant violation using reversible fixture |
| Cloud/IaC/CI/directory indicator | cloud/CI/AD specialist | In-scope identity-policy-resource relationship is unsafe |
| Client-side messaging or realtime event | browser/WebSocket skills | Attacker-controlled state crosses an enforced trust boundary |

## Evidence and Handoff Rules

- Do not call a banner, documentation file, public error, blocked request,
  scanner label, or CVE version match a confirmed vulnerability by itself.
- Keep a per-surface coverage record: observed signals, dispatched skills,
  baseline, validation result, and exact missing prerequisite if unresolved.
- Store compact shared-memory facts that other agents can use: component →
  version; endpoint → roles tested; identity → tenant; source artifact →
  deployment confidence; request layer → observed normalization behavior.
- Escalate a useful relationship as a chain hypothesis only when each edge has
  evidence. Use `record_thinking` for an unproven path and state the next
  safe validation step; never merge it with confirmed findings.
