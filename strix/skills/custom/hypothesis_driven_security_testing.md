---
name: hypothesis-driven-security-testing
description: Evidence-led creative security investigation for product-specific trust-boundary mismatches, negative-space controls, and novel multi-step hypotheses
---

# Hypothesis-Driven Security Testing

Skills are a memory aid and routing catalogue, **not a closed list of attacks
the assessment is allowed to consider**. Use this skill when the target's own
behavior, architecture, source, integration, or business workflow suggests a
security failure that is not adequately represented by one existing
vulnerability family.

The work remains narrow and evidence-led: one investigator owns one concrete
hypothesis on one component or trust boundary. Do not create a generic
"creative testing" agent and do not turn imagination into unbounded probing.

## Hypothesis Contract

Write the following before touching the target. Store a compact version in a
shared note or shared memory so other agents can reuse or challenge it.

```text
surface / component:
observed fact(s):                 # source, recon, captured behavior, or prior finding
expected invariant or control:    # what must remain true to protect the asset
suspected mismatch:               # why the observed facts may violate it
attacker capability:              # anonymous, authorized user, tenant A, etc.
minimal differentiating test:     # one bounded comparison against baseline
success condition:                # protected action/data/control that must differ
stop condition:                   # rate/state/scope/evidence limit
next route if positive:           # skill or focused validator, if one becomes clear
```

A hypothesis without observed facts or an expected protected invariant is a
brainstorming note, not a test task. Do not spend target requests on it.

## Product-Specific Sources of Hypotheses

Look for mismatches rather than merely enumerating known vulnerability names.

### Cross-Interface and Policy Drift

Compare equivalent operations across UI/API/mobile/legacy endpoints, REST and
GraphQL, synchronous and asynchronous paths, batch and single-item endpoints,
or normal and admin-facing routes. Hypothesize only when the same protected
operation has two policy enforcement points that may disagree.

Examples of useful questions:

- Does the UI hide an action that an API route still authorizes differently?
- Does an export, webhook, background worker, or retry path re-check the same
  tenant and role policy as the originating request?
- Does a legacy version or alternate content type reach the same state change
  but bypass an expected validation or audit control?

### Negative-Space Controls

Ask what security control must exist for the product promise to hold, then
look for one authorized, minimally invasive way to observe it.

- A recovery, invitation, device-trust, or account-linking flow should bind
  identity, expiry, and intended account.
- A tenant product should bind every read, write, export, notification, and
  asynchronous consumer to tenant scope.
- A quota/payment/approval workflow should have server-side state and
  idempotency invariants, not just UI sequencing.
- A private artifact should have a revocation/authorization decision at every
  retrieval path, including previews and transformed copies.

Absence of a visible control is not proof. Define the particular protected
outcome that would demonstrate the missing enforcement.

### Representation and Time Mismatches

Propose a test when two components may interpret the same object differently:
role claim versus database role, display amount versus charged amount,
canonical URL versus routed URL, original filename versus stored object,
request-time authorization versus delayed worker behavior, or cache key versus
origin identity. Change one representation or timing dimension at a time and
keep state reversible.

### Composition and Trust-Boundary Pivots

Use confirmed low-severity facts as possible edges, not automatic exploit
chains. A source-map route plus a client-side feature flag, a weak boundary
plus an export path, or a callback feature plus a privileged worker can justify
a focused hypothesis. Each edge needs its own evidence; use `record_thinking`
when the end-to-end path remains plausible but unproven.

## Test Discipline

1. Read the threat model and search shared memory before testing so the
   hypothesis adds coverage rather than repeats another agent.
2. Establish a baseline with the same authorized role, resource, and workflow.
3. Run the smallest differential experiment that could falsify the hypothesis.
4. Preserve request IDs, source locations, timing, and state transitions needed
   for an independent validator to replay the conclusion.
5. If the result maps to a known class, hand off to a focused specialist skill
   for deeper validation. If not, remain focused on the original invariant.
6. Stop on rate-limit, scope, destructive-state, privacy, or success-condition
   boundaries; do not broaden into enumeration, credential guessing, lateral
   movement, or data collection.

## Outcomes

- **Confirmed:** A controlled comparison demonstrates an unauthorized protected
  consequence. Send it to independent validation and report it normally.
- **Ruled out:** Record the exact server-side control or invariant that held in
  both baseline and variant; do not call an unexplained error a mitigation.
- **Informational:** A security-relevant design observation lacks a supported
  validation method; name the exact method gap.
- **Thinking:** The evidence supports a plausible route but a concrete
  prerequisite is unavailable. Call `record_thinking` with the proof gap and a
  safe next test. Thinking is never a confirmed finding or severity input.

## Root-Agent Completion Check

For a standard or deep run, verify that every material high-value trust
boundary has either:

1. one product-specific hypothesis tested or explicitly ruled out as not
   meaningful; or
2. an explicit rationale why no evidence-based non-taxonomy hypothesis exists.

In deep mode this check is mandatory for every material component. In standard
mode apply it to each distinct high-value trust boundary. Quick mode may use it
for a high-value signal but remains time-boxed.
