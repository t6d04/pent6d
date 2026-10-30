---
name: web-attack-surface
description: Target-bounded web attack-surface discovery combining historical URLs, hidden parameters, JavaScript analysis, visual triage, sensitive-file checks, and technology-specific pivots
---

# Web Attack-Surface Discovery

Use this skill after the initial asset inventory is available and before
vulnerability specialists are dispatched. The output is an evidence-backed
map of reachable web surfaces, not a generic scanner dump.

## Target Boundaries and Active Testing

Use the run's declared targets and project instruction as the operational
boundary. A discovered hostname is eligible for active testing when it matches
an explicitly supplied target or wildcard; do not expand to unrelated
third-party neighbors merely because DNS, certificates, a CDN, or a bundle
mentions them. This is a target-selection rule, not a separate authorization
workflow, and it does not downgrade matching hosts to passive-only review.

For every active request:

1. Apply the target's agreed request rate, concurrency, depth, and duration.
   Use explicit limits on every crawler/fuzzer command.
2. Treat API keys and returned secrets as sensitive evidence. Redact them in
   notes and do not reuse credentials against a different target.
3. Keep provenance and the target match on every observation so downstream
   specialists know why the host was selected.

## Required Inventory

Persist observations incrementally with `record_recon` (batches up to 100),
not just the final narrative. Reuse this run's `list_recon` inventory. Capture
at least one screenshot for every distinct in-scope alive hostname using
agent-browser, then pass the actual PNG/JPEG /workspace path to `record_recon`
immediately so it survives sandbox cleanup. Aliases and routes on one canonical
hostname may share the capture. Include the final URL, source and observation
time; a live host without durable screenshot evidence cannot pass recon
finalization.
Redact secrets and personal data before recording/capturing. JS leak candidates
use kind=js_leak with redacted evidence and confidence=unverified until checked;
record JS/source-map URLs separately as kind=javascript. A recon observation
is not a vulnerability report; link confirmed reports with finding_id.

At the end of each workstream, call `record_recon_coverage` with the tools and
a concise evidence summary describing what was established. A tool name alone
is not evidence. Use `not_applicable` only when the target genuinely has no such
surface; use `blocked` when a prerequisite prevented testing. Do not silently
omit a phase.

For each in-scope asset, retain:

- canonical URL/host, scheme, port, IP and source of discovery;
- scope decision and attribution evidence;
- an explicit attribution level (`confirmed`, `likely`, `unknown`, or
  `out_of_scope`) with the certificate, DNS ownership, vhost, organization,
  cloud-account, or program-scope evidence supporting it;
- HTTP status, title, server, technology/version, TLS certificate names and
  redirect chain;
- route, method, parameter, content type, authentication role and object/tenant
  identifiers where observed;
- source artifact (live page, JavaScript, CT, archive, DNS, scanner) and the
  exact request or file that supports the observation;
- recommended downstream skill and confidence (`observed`, `inferred`, or
  `unverified`).

Do not treat a URL, technology fingerprint, or scanner match as a confirmed
vulnerability. It is a lead until a specialist validates security impact.

## Discovery Pipeline

### 1. Passive and Historical Expansion

Start with the existing `asset_discovery` workflow, then enrich the seed set
only with authorized sources:

- certificate transparency and TLS SANs (`crt.sh`, `httpx -tls-grab`);
- passive DNS, ASN/IP ownership, Shodan/OTX/urlscan and organization data;
- GitHub/code-host searches for hostnames, API routes, source maps, and public
  deployment metadata;
- historical URLs from GAU, Wayback, and other archive sources.

Record the source and timestamp for every result. Historical or passive data is
not proof that the route or host is still live.

### 2. DNS Permutation and Resolution

Use observed naming conventions to generate bounded candidates with `alterx` or
an equivalent permutation tool, then resolve with `dnsx`/`dig`. Prefer targeted
prefixes such as `api`, `staging`, `dev`, `admin`, `grafana`, and `git` derived
from real evidence over a large blind dictionary.

Deduplicate before probing. A DNS answer alone is not authorization and a
provider/CNAME answer is not proof of ownership.

### 3. Live HTTP and Service Classification

Probe in-scope hosts with `httpx` and capture status, title, server,
technology, redirects, TLS SANs, favicon/response hashes, and content length.
Use `naabu`/`nmap` only within the approved port range and with conservative
rate limits. Classify each service by function:

- public application, API, authentication, admin, storage, CI/CD, observability;
- documentation, debug/health endpoint, VCS, mail, proxy, or non-HTTP service.

Prioritize exposed admin/debug/observability and versioned services, but leave
impact testing to the matching specialist.

### 4. Crawling and Known Files

For live web applications use a bounded Katana crawl with JavaScript and known
file extraction. Use `gospider`/Hakrawler as a second pass only when the first
pass is unexpectedly thin. Keep depth, duration, page count, response size,
scope, and rate explicit; emit URL-only output when response bodies are not
needed.

Check `robots.txt`, `sitemap.xml`, OpenAPI/Swagger, GraphQL discovery, common
health/debug paths, and alternate HTTP methods when the normal request makes
them relevant. A discovered route is a candidate surface, not a finding.

### 5. Historical URL and Parameter Mining

Normalize and deduplicate current plus historical URLs. Group by route and
parameter rather than sending every archived URL back to the target. Use
`gf`/equivalent patterns to prioritize `url`, `redirect`, `file`, `path`,
`id`, `query`, `callback`, `template`, and upload-like parameters.

Use `Arjun`, ParamSpider, or Kiterunner only on an authorized endpoint and with
bounded methods, wordlists, concurrency, and request rate. Preserve a baseline
request and compare status, length, reflection, and error changes before
handing a parameter to an injection specialist.

### 6. JavaScript and Client-Side Analysis

Collect same-scope JavaScript, source maps, route bundles, and XHR/fetch
references. Extract:

- API routes, alternate versions, GraphQL operations, WebSocket URLs;
- parameter names, feature flags, role/tenant identifiers and upload paths;
- public configuration and accidentally exposed secrets.

Use JS-Snooper/jsniper, LinkFinder, SecretFinder, `rg`, or a small parser as
appropriate. A string that looks like a key is only an observation until its
scope, validity, privilege, and target association are confirmed. Route secrets
to `information_disclosure`, source-artifact, cloud, or authentication skills;
do not authenticate with them automatically.

### 7. Content, Sensitive Files, and Technology Pivots

For authorized content discovery, run the two fixed dictionaries as independent
bounded jobs and merge normalized results:

- `/workspace/wordlists/seclists-common.txt`
- `/workspace/wordlists/dirsearch-dicc.txt`

Do not create a Cartesian-product wordlist or download replacement dictionaries
at runtime. Look for sensitive extensions and repository/config artifacts such
as `.env`, `.log`, `.sql`, `.bak`, `.zip`, source maps, `.git`, and deployment
manifests. Confirm disclosure and sensitivity before reporting.

Fingerprint framework/CMS/library versions and route to the corresponding
framework, `dependency_cve_scanning`, `default_credentials`, or
`cve_exploit_validation` skill. If WordPress is in scope, WPScan is a useful
technology-specific option; it is not a substitute for validation.

### 8. Visual and Human-Readable Triage

Take bounded screenshots of live hosts (Aquatone or the existing browser
tooling) and cluster similar pages by title, favicon, response hash, and
technology. Use visual differences to find staging panels, dashboards, login
portals, debug consoles, and exposed documentation. Screenshots support
prioritization; they do not prove authorization or exploitability.

## Recon-to-Skill Dispatch

The handoff must contain concrete rows in this form:

```text
surface → observed evidence → risk hypothesis → recommended skill(s) → proof gap
```

Examples:

- object/tenant IDs → two roles see the same route with different IDs → IDOR or
  function-level authorization → `idor`, `broken_function_level_authorization`;
- callback/import/preview URL → server accepts a user-controlled URL → SSRF or
  open redirect → `ssrf`, `open_redirect`;
- JavaScript route with token/role metadata → client exposes privileged API path
  → authz or information disclosure → `authentication_bypass`, `idor`,
  `information_disclosure`;
- upload/download or file parameter → path/content-type/filename surface → file
  upload or traversal → `insecure_file_uploads`, `path_traversal_lfi_rfi`;
- CMS/framework/version → exact product and version evidence → known CVE or
  default credential candidate → matching framework, `cve_exploit_validation`,
  `default_credentials`;
- WAF/block/parser mismatch → different status/body under equivalent encoding →
  filter or WAF bypass → `waf_evasion`, `input_filter_bypass` plus sink skill.

## Completion Criteria

Recon is complete only when the handoff records:

1. the in-scope host/route inventory and any unverified leads;
2. the sources and timestamps for passive, historical, and active observations;
3. live probing, crawl, parameter, JavaScript, sensitive-file, and technology
   coverage (including explicit clean/not-applicable outcomes);
4. authentication roles, object/tenant boundaries, and state-changing flows
   that need specialist testing;
5. a prioritized dispatch matrix and open proof gaps.

“No obvious bug found” is not a recon completion statement.

## Common False Positives

- archived routes that no longer exist or now belong to another tenant;
- CDN/provider neighbors discovered through a shared IP or certificate;
- source-map strings, test fixtures, documentation, or dead JavaScript routes;
- public configuration values that are non-secret or privilege-free;
- framework fingerprints inferred from a banner without version confirmation;
- directory responses that are generic 404/soft-404 pages;
- parameter differences caused only by cache, redirect, rate limit, or WAF noise.

## Summary

Build a provenance-preserving, scope-filtered web map; enrich it with historical
URLs, parameters, JavaScript, sensitive files, and visual clues; then dispatch
each concrete surface to a focused vulnerability specialist. Recon is valuable
when it reduces uncertainty for the next agent, not when it produces the largest
number of URLs.
