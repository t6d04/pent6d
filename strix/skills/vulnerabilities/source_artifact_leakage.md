---
name: source-artifact-leakage
description: Source maps, build artifacts, documentation, repository metadata, and client bundle disclosure analysis
---

# Source and Build Artifact Leakage

Public build artifacts can reveal source code, routes, schemas, environment
names, credentials, internal hostnames, and feature flags. Classify each item
by the information actually exposed and the authorization it enables.

## Sources

- JavaScript source maps, chunk manifests, mobile assets, generated SDKs, API
  descriptions, stack traces, debug bundles, and archived releases.
- Repository metadata, forgotten configuration backups, package manifests,
  CI artifacts, and container/image metadata.

## Validation

Fetch only publicly reachable artifacts within scope. Verify whether the
artifact exposes restricted source, a live secret, an undocumented API, or
merely public build metadata. Redact values that could be reused and hand
discovered endpoints to `shadow_api` or `spa_api_discovery` for separate
authorization testing.

## Discovered Source Pivot

When a black-box target exposes source code, repository metadata, source maps,
deployment archives, package bundles, or enough artifacts to reconstruct server
or client source, treat it as a source-code pivot for that same authorized
target. The objective is to turn the leak into local-code-style review, then
validate whether the reviewed code is actually the code serving the current
target.

### 1. Acquire a bounded source snapshot

- Attempt to dump the complete source tree from the exposed artifact set when
  the retrieval is public, in-scope, non-destructive, and bounded by the
  target's rate and scope limits.
- Prefer purpose-built reconstruction for the artifact type: source-map
  recovery for JavaScript maps, DVCS reconstruction for exposed `.git`/`.svn`
  metadata, archive download for deployment packages, and manifest-guided fetch
  for chunk/source listings.
- Save recovered material under a dedicated directory such as
  `/workspace/.strix-source-artifacts/<target-host>/<artifact-id>/source` with
  a manifest containing source URL, fetch time, hashes, file count, byte count,
  and any failed paths. Do not mix recovered code into an existing repository.
- Treat every downloaded archive, repository object, source map, and recovered
  filename as attacker-controlled. Before writing a file, resolve its final
  path and require it to remain below the artifact directory. Reject absolute,
  drive-qualified, UNC, device, and `..` paths; reject symlinks, hardlinks, and
  special files; and never let archive extraction overwrite an existing file
  outside that artifact's directory.
- Enforce collection and extraction budgets. Unless the verified scope supplies
  stricter limits, stop at 20,000 files, 25 MiB for one file, or 250 MiB total
  expanded content. Detect archive nesting and suspicious compression ratios;
  preserve the manifest and partial safe snapshot when a limit is reached.
- Do not follow discovered links to external domains, repositories, package
  registries, storage buckets, or sibling hosts unless they are explicitly in
  the system-verified scope. Passive attribution is allowed; active testing is
  not.
- Stop collection when it becomes unbounded, noisy, destructive, rate-limit
  risky, or clearly leaves scope. Preserve the partial snapshot and record why
  full dump was not possible.

If a complete dump is impossible, immediately analyze the returned partial
content instead of waiting for perfect acquisition. A source map with only a
few high-value original files, a stack trace with source excerpts, or one
configuration backup can still drive targeted validation.

### 2. Run local-code-style review

Once any meaningful source snapshot exists, create or hand off to a dedicated
local-code review task:

- Spawn a specialist child named like `Local Code Review - Discovered Source`.
- Give the child the snapshot path, source manifest, original black-box target,
  in-scope URL/domain list, and any observed runtime fingerprints.
- Set `source_review=True` on `create_agent`. This promotes that child to the
  source-aware/white-box prompt baseline and automatically loads internal
  analysis skills such as `analysis/source_aware_discovery` without passing an
  internal skill name through the public skill validator.
- Assign the selectable `custom/source_aware_sast` skill and, when needed, one
  vulnerability-class skill for the candidate under review. A typical call is
  `create_agent(name="Local Code Review - Discovered Source", task="Review the
  recovered snapshot at <path>; do not execute it; correlate candidates only
  with the supplied in-scope target", source_review=True,
  skills=["custom/source_aware_sast"])`.
- Instruct the child to run the normal local-code baseline where feasible:
  Semgrep, secrets scan, dependency/config review, AST/route mapping, and
  targeted manual dataflow review. For very partial source, it should perform
  best-effort manual review and record the coverage gap.
- Store scanner outputs below
  `/workspace/.strix-source-artifacts/<target-host>/<artifact-id>/analysis`.
  Override the shared `/workspace/.source-aware` examples from the generic SAST
  playbook so separate recovered artifacts and ordinary repositories cannot
  overwrite or contaminate one another's evidence.
- Do not execute recovered programs, package-manager lifecycle scripts, build
  files, tests, Git hooks, repository-provided scanner plugins/configuration, or
  installers in the shared scan sandbox. Use data-only parsing and explicitly
  selected trusted scanner rules. Dynamic validation means sending bounded
  requests to an authorized live target, not starting untrusted recovered code.

This is the Strix equivalent of calling `local_code` for recovered source:
`local_code` remains a scan-start target type, while `source_review=True`
promotes a mid-scan child to the same source-aware prompt baseline after the
recovered source has been materialized in the shared workspace. The promotion
does not expand the verified network scope.

### 3. Prove whether the source belongs to the current target

Do not assume leaked source is live for the target just because it came from
the target. Establish a provenance binding before using static findings as
evidence for the current application.

Useful binding signals include:

- build IDs, commit SHAs, release versions, source-map `sourcesContent`, chunk
  hashes, asset filenames, sourcemap references, and package lock versions
- route names, API schemas, controller paths, stack-trace frames, error
  messages, templates, feature flags, translation keys, and GraphQL operation
  names observed on the live target
- framework fingerprints, headers, cookie names, session formats, dependency
  versions, and unique strings shared between the snapshot and HTTP responses

Classify the binding as one of:

- `current_target_confirmed` - strong match to the current in-scope target
- `current_target_probable` - multiple independent matches but no exact build
  proof
- `unknown_or_stale` - code is plausible but cannot be tied to the live target
- `different_in_scope_target` - belongs to another authorized target
- `out_of_scope_target` - appears to belong to an asset outside verified scope

Record this classification in a note and in coverage evidence for the reviewed
surface. Unknown or stale source can guide testing, but it is not enough for a
validated vulnerability by itself.

### 4. Validate candidates dynamically

If the source is confirmed or probable for the current in-scope target, use the
code review to drive dynamic validation against that same target:

- Map source entrypoints to concrete URLs, methods, parameters, auth states,
  tenants, and roles.
- For each plausible bug, spawn the usual vulnerability-specific validation
  agent with the relevant code path and candidate exploit condition.
- File a vulnerability only after the dynamic proof succeeds, or when the
  applicable reporting rule explicitly allows a static/dependency finding.
- Include both source evidence and HTTP/proxy evidence in the final report;
  attach code locations and remediation when source is sufficient.

If the source belongs to another in-scope target, route the candidate to that
target's testing flow and do not test it against the original target unless
the binding changes.

Treat the disclosure itself separately from any vulnerability candidates found
inside the recovered code. If an in-scope endpoint exposes non-public source,
the successful retrieval plus a benign/denied control is dynamic evidence of
information disclosure on that in-scope endpoint. File that disclosure with
`create_vulnerability_report` when it meets the finding bar even if provenance
shows that the leaked code belongs to a different or out-of-scope application.
Describe the suspected owner only as impact/provenance; do not claim or test a
vulnerability in that other application.

If the source appears to belong to an out-of-scope asset, do not probe or test
that asset. Record its hashes, suspected owner/host, and scope boundary in the
in-scope disclosure report. If the exposure itself does not meet the reporting
bar (for example, the material is intentionally public), create a durable note
and `record_coverage(outcome="needs_follow_up")` entry instead. A note in the
`findings` category is never a substitute for a vulnerability report.

## Recon artifact handoff

Every confirmed or strongly evidenced source leak must be written to the
run-scoped recon inventory with `record_source_leak`. Use
`source_location_type=local_path` and `source_download_status=downloaded` when
a bounded snapshot was saved locally; use `source_location_type=web_url` and
`source_download_status=online_only` when the artifact cannot be downloaded but
is still readable at a target URL. Keep the exposed URL in `value`, preserve
the provenance in `source`/`evidence`, and never claim a local copy exists when
only the online artifact was inspected.
