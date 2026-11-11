---
name: standard
description: Balanced security assessment with systematic methodology and full attack surface coverage
---

# Standard Testing Mode

Balanced security assessment with structured methodology. Thorough coverage without exhaustive depth.

## Approach

Systematic testing across the full attack surface. Understand the application before exploiting it.

## Phase 1: Reconnaissance

**Whitebox (source available)**
- Map codebase structure: modules, entry points, routing
- Run `semgrep` first-pass triage to prioritize risky flows before deep manual review
- Run at least one AST-structural mapping pass (`sg` and/or Tree-sitter), then use outputs for route, sink, and trust-boundary mapping
- Keep AST output bounded to relevant paths and hypotheses; avoid whole-repo generic function dumps
- Identify architecture pattern (MVC, microservices, monolith)
- Trace input vectors: forms, APIs, file uploads, headers, cookies
- Review authentication and authorization flows
- Analyze database interactions and ORM usage
- Check dependencies and repo risks with `trivy fs`, `gitleaks`, and `trufflehog`
- Understand the data model and sensitive data locations

**Blackbox (no source)**
- Crawl application thoroughly, interact with every feature
- Enumerate endpoints, parameters, and functionality
- Fingerprint technology stack
- Map user roles and access levels
- Capture traffic with proxy to understand request/response patterns

After recon, build a canonical host ledger. Every in-scope host/subdomain
whose service is `alive` must be explicitly assigned to a specialist and have
a completed host-coverage handoff; do not finish with only the highest-priority
hosts tested.

## Phase 2: Business Logic Analysis

Before testing for vulnerabilities, understand the application:

- **Critical flows** - payments, registration, data access, admin functions
- **Role boundaries** - what actions are restricted to which users
- **Data access rules** - what data should be isolated between users
- **State transitions** - order lifecycle, account status changes
- **Trust boundaries** - where does privilege or sensitive data flow

## Phase 3: Systematic Testing

Test each attack surface methodically. Spawn focused subagents for different areas.

### Product-Specific Hypothesis Pass

After skill-based routing, apply one evidence-backed creative hypothesis to
each distinct high-value trust boundary. Skills are useful methods, not an
exhaustive list of possible application failures. Compare the expected
invariant with observed behavior across UI/API/legacy/async paths, roles,
representations, and workflow transitions. Use
`hypothesis_driven_security_testing` for a focused `Hypothesis Explorer` child
with `role="hypothesis"` and a short name when no existing vulnerability family
describes the suspected mismatch. Set `testability` on every Thinking record
and test `testable_now` hypotheses first. Keep the test bounded, reversible, and
baseline-driven; a plausible but unproven result is Thinking, not a finding.

**Input Validation**
- Injection testing on all input fields (SQL, XSS, command, template)
- File upload bypass attempts
- Search and filter parameter manipulation
- Redirect and URL parameter handling

**Authentication & Session**
- Brute force protection
- Session token entropy and handling
- Password reset flow analysis
- Logout session invalidation
- Authentication bypass techniques

**Access Control**
- Horizontal: user A accessing user B's resources
- Vertical: unprivileged user accessing admin functions
- API endpoints vs UI access control consistency
- Direct object reference manipulation

**Business Logic**
- Multi-step process bypass (skip steps, reorder)
- Race conditions on state-changing operations
- Boundary conditions: negative values, zero, extremes
- Transaction replay and manipulation

## Phase 4: Exploitation

- Every finding requires a working proof-of-concept
- Demonstrate actual impact, not theoretical risk
- Chain vulnerabilities to show maximum severity
- Document full attack path from entry to impact
- Use Python scripts through `exec_command` for complex exploit development

## Phase 5: Reporting

- Document all confirmed vulnerabilities with reproduction steps
- Severity based on exploitability and business impact
- Remediation recommendations
- Note areas requiring further investigation

## Chaining

Always ask: "If I can do X, what does that enable next?" Keep pivoting until reaching maximum privilege or data exposure.

Prefer complete end-to-end paths (entry point → pivot → privileged action/data) over isolated findings. Use the application as a real user would—exploit must survive actual workflow and state transitions.

When you discover a useful pivot (info leak, weak boundary, partial access), immediately pursue the next step rather than stopping at the first win.

## Mindset

Methodical and systematic. Document as you go. Validate everything—no assumptions about exploitability. Think about business impact, not just technical severity.
