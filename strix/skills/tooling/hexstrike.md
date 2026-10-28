---
name: hexstrike
description: Use the local HexStrike MCP sidecar for bounded recon and scanner enrichment, then persist normalized results for every downstream agent
---

# HexStrike MCP workflow

HexStrike is an optional local MCP sidecar. It is an execution backend, not a
second workflow authority. Use it only for platform-verified, in-scope targets
and keep the Pent6d scope, rate limits, evidence gates, and reporting rules in
force.

## Discover and select tools

When MCP is available, call `list_mcps()` once early. If a connection named
`hexstrike` is present, use `search_mcp_tools(connection="hexstrike", query=...)`
before calling a tool, then fetch the exact schema with
`get_mcp_tool_schema`. Never guess an argument shape. If the connection is not
available, continue with Pent6d's native tools and record the fallback.

Prefer the bounded HexStrike tools in this order:

- Recon: `subfinder_scan`/`amass_scan` -> `httpx_probe` -> `katana_crawl`.
- Content discovery: `dirsearch_scan` or `ffuf_scan`, only with the approved
  fixed wordlists and the target's agreed rate/concurrency limits.
- Focused validation: `nmap_scan`, `nuclei_scan`, `wafw00f_scan`,
  `arjun_parameter_discovery`, or `dalfox_xss_scan` only when recon supplies a
  concrete host, endpoint, parameter, or technology signal.
- `server_health` is a diagnostic check; it is not vulnerability evidence.

Do not run every HexStrike scanner indiscriminately. Deduplicate against the
shared recon inventory and existing attack-graph tasks. A HexStrike result is a
lead until the target-side request/response or source trace confirms it.

## Persist every useful result

`call_mcp` automatically stores a bounded, redacted evidence excerpt in this
run's shared memory with tags including `mcp`, `hexstrike`, and the tool name.
Treat that record as a hand-off pointer, not as a raw transcript. After each
successful recon-oriented call, also normalize actionable rows into
`record_recon`:

- subdomains/hosts -> `kind=subdomain` or `service`;
- live HTTP results -> `kind=endpoint` with the observed status/title and
  `alive=alive` (any real origin status, including 4xx/5xx, is alive);
- technologies/banners -> `kind=technology`;
- JavaScript URLs or exposed source -> `kind=javascript`/`source_leak`;
- tool output without target-side confirmation -> `confidence=unverified`.

Use a source such as `hexstrike:<tool>` and include the exact target, command
parameters, timestamp, status, and a concise redacted evidence summary. Do not
store cookies, bearer tokens, passwords, API keys, full raw crawls, or entire
scanner output in shared memory. Save only compact facts that another agent can
query with `search_shared_memory`, and point to durable local artifacts when a
tool writes one.

After recording, call `remember_shared_memory` for high-value facts that are not
representable as a recon row (for example a technology version, a scanner
limitation, or a validated endpoint relationship). Before dispatching a
specialist, call `finalize_recon` only after the complete structured inventory
and required screenshots are present.

## Failure and validation

If a HexStrike call fails, preserve the failure as an evidence/coverage note,
try the smallest native fallback, and do not mark the target clean. If the
result suggests a vulnerability, pass the endpoint and evidence IDs to the
appropriate specialist; do not file a finding from scanner output alone.
Validate with a bounded request or code trace, attach proxy exchange IDs when
applicable, and report only after the normal counterevidence and deduplication
checks.
