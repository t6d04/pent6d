---
name: verified-whitebox-audit
description: Evidence-gated white-box audit protocol with independent verification, coverage critics, and safe local execution boundaries
---

# Verified White-Box Audit Protocol

Use this protocol whenever Strix receives local source code. It strengthens the
ordinary source-aware workflow with deterministic coverage, independent review,
and honest unresolved states. It does **not** replace Strix's authorized
black-box or combined-mode validation: when an in-scope live target exists,
dynamic validation may use it after source review has identified a concrete
candidate.

## Audit Contract

The root agent owns the plan, coverage reconciliation, and final scan report.
Hunters investigate bounded units; they do not report their own source-derived
candidate. A separate verifier must re-read the cited source and try to refute
the claim before it is filed.

Keep these outcomes distinct:

- `confirmed`: a complete source trace plus a bounded observed result or an
  authorized live validation establishes a real security-boundary violation.
  The independent verifier, not the hunter, files the report.
- `needs_validation`: the source trace is concrete but one decisive runtime or
  deployment fact is unavailable. Record it with
  `record_coverage(outcome="needs_follow_up")`, including the exact missing
  fact and a safe local or owner-observed validation plan. Do not assign it a
  severity or file it as a vulnerability report.
- `rejected`: a specific control, source fact, or bounded validation disproves
  the candidate. Record the control and its location with
  `record_coverage(outcome="ruled_out")`.

Static scanner hits, missing best practices, same-principal effects, and
unreproduced speculation are not confirmed findings.

## Phase 0 — Establish Source Identity and Execution Boundary

Before spawning hunters, identify the repository root, reviewed revision (Git
commit when available), dirty-worktree state, in-scope paths, build system, and
whether a live target is also authorized. Record this as a methodology note so
later agents do not conflate generated, stale, or unreviewed files with the
reviewed source.

Read source freely, but execute target-controlled code only when the active
runtime can provide all of the following: no external network for that process,
an allowlisted non-secret environment, a read-only target/toolchain, a
dedicated scratch path, and explicit CPU, memory, process, disk, file-size, and
wall-clock bounds. If the runtime cannot demonstrate a required control, do not
run target builds/tests/installers; preserve the exact limitation as
`needs_validation`. Never install or fetch dependencies during a white-box
validation run.

When source execution is permitted, use dummy accounts/data and the smallest
local check that settles the boundary. Stop after the minimum observable
effect. Do not expose another agent's artifacts, the host environment,
credentials, or a shared service to target-controlled code.

## Phase 1 — Parallel Reconnaissance

Create focused reconnaissance children (or perform the equivalent work in a
small repository) for these independent questions:

1. **Architecture and operation:** product roles, languages, frameworks,
   packages, source-visible deployment paths, local build/test commands, and
   their writes/network behavior.
2. **Principals and controls:** identity establishment, authorization,
   tenant/resource isolation, privilege changes, recovery/revocation, and
   controls that require unobserved deployment facts.
3. **Entrypoints and sinks:** HTTP/RPC, file/archive, CLI/config, jobs/queues,
   plugins/CI, cloud/IAM, LLM/tool, browser/mobile, and local IPC inputs;
   trace their important copies and sinks.

Each child returns repository-relative paths and line references. The root
turns the returned facts into a compact target/threat model before hunting.

## Phase 2 — Deterministic Coverage-Led Hunting

Define one coverage unit for each material combination of:

`entry surface × trust boundary × subsystem × attack class`

Use stable, readable values in `record_coverage`:

- `surface`: `WB::<subsystem>::<entrypoint>`
- `risk_area`: `WB::<boundary>::<attack class>`

This makes a single coverage row a durable identity for the same unit and
prevents two agents silently treating related work as complete. For a scoped
review, record excluded units as `not_applicable` only when the attack class
truly cannot apply; otherwise use `needs_follow_up` and name the scope or
budget boundary.

Assign a hunter only closely related units in one subsystem. Its task must
state: source root, starting paths, entrypoint, lower-trust principal,
protected resource, expected control/invariant, selected vulnerability skills,
and units already owned by peers. The hunter should:

- trace input through parsing, identity, authorization, normalization, stored
  state, retry/error paths, and the final sink;
- compare sibling, legacy, batch, migration, and fallback paths for equivalent
  controls rather than merely finding one safe sibling;
- exercise boundary-relevant sad paths (empty, duplicate, stale, revoked,
  reordered, malformed, concurrent, rollback, and failed-dependency states);
- return candidates with a stable root-cause fingerprint, source trace,
  strongest visible counter-control, exact conditions, and minimum validation
  method; and
- return newly discovered but unowned boundaries to the root as coverage gaps
  rather than investigating peer-owned work.

After each wave, spawn a separate `Whitebox Coverage Critic` with
`source_review=True` and `custom/source_aware_sast`. It reads the threat model,
`list_coverage`, completed-agent summaries, and source map; it must identify
unassigned material entry/boundary/class combinations, duplicate coverage, and
claims closed without a named control. The root assigns accepted gaps in a new
wave or records them as `needs_follow_up` with the explicit budget/scope reason.

## Phase 3 — Fresh Candidate Verification

For every unique source-derived candidate, the root spawns a verifier that did
not hunt that candidate. Use `create_agent(source_review=True, ...)` with the
candidate's vulnerability skill, trace, code locations, strongest expected
control, exact preconditions, and safe test boundary.

The verifier must independently:

1. Re-read every cited source location and establish lower-trust entrypoint →
   control → sink/effect.
2. Try the strongest refutation: visible authorization, normalization,
   containment, lifecycle, framework, and deployment-visible controls.
3. Run only the narrowest permitted local check or authorized live validation.
4. Check that impact, confidence, and remediation describe only the observed
   result.
5. Resolve exactly one of `confirmed`, `needs_validation`, or `rejected`.

Only a verifier may call `create_vulnerability_report` for a source-derived
candidate. It must include source locations, counterevidence, a concrete fix,
and dynamic/proxy evidence when live HTTP validation was used. A verifier that
cannot establish a decisive fact records the proof gap; it must not upgrade a
hunter's wording by assumption.

## Phase 4 — Final Reconciliation

Before `finish_scan`, the root calls `list_coverage` and checks every
white-box unit. For each unit, there must be one of: reported finding,
source-visible control that ruled it out, documented no-issue test, or exact
proof gap. Reconcile duplicate rows with `update_coverage`; do not leave a
closed row beside a newer contradictory conclusion.

For deep reviews, dispatch a final independent record reviewer for each
confirmed source finding. It verifies the source locations, principal,
preconditions, observed effect, severity, and fix without relying on the
hunter's conclusion. If that review changes the conclusion, update the filed
report and its coverage row before finishing.

When prior Strix runs are available, compare the relevant current source before
reusing their conclusions. An unchanged source location can inform priority,
but a prior `reported`, `needs_follow_up`, or `ruled_out` row never suppresses
the current unit without a current source re-check.

## Anti-Patterns

- Letting a hunter report its own candidate without adversarial review.
- Marking unknown deployment behavior as either safe or exploitable.
- Calling a scanner result a vulnerability without an input/control/effect
  trace.
- Treating a safe sibling as proof that every sibling is safe.
- Calling source-only evidence a live-target result.
- Leaving an unassigned unit invisible because of budget, agent limits, or
  implementation difficulty.
