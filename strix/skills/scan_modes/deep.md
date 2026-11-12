---
name: deep
description: Exhaustive security assessment with maximum coverage, depth, and vulnerability chaining
---

# Deep Testing Mode

Exhaustive security assessment. Maximum coverage, maximum depth. Finding what others miss is the goal.

## Approach

Thorough understanding before exploitation. Test every parameter, every endpoint, every edge case. Chain findings for maximum impact.

## Phase 1: Exhaustive Reconnaissance

**Whitebox (source available)**
- Map every file, module, and code path in the repository
- Start with broad source-aware triage (`semgrep`, `ast-grep`, `gitleaks`, `trufflehog`, `trivy fs`) and use outputs to drive deep review
- Execute at least one structural AST pass (`sg` and/or Tree-sitter) per repository and store artifacts for reuse
- Keep AST artifacts bounded and query-driven (target relevant paths/sinks first; avoid whole-repo generic function dumps)
- Use syntax-aware parsing (Tree-sitter tooling) to improve symbol, route, and sink extraction quality
- Trace all entry points from HTTP handlers to database queries
- Document all authentication mechanisms and implementations
- Map authorization checks and access control model
- Identify all external service integrations and API calls
- Analyze configuration for secrets and misconfigurations
- Review database schemas and data relationships
- Map background jobs, cron tasks, async processing
- Identify all serialization/deserialization points
- Review file handling: upload, download, processing
- Understand the deployment model and infrastructure assumptions
- Check all dependency versions and repository risks against CVE/misconfiguration data
- For quick CVE lookups on a named product/version, use `vulnx search <query>`
  (ProjectDiscovery's CVE database) before falling back to web_search
- Treat every plausible in-scope CVE as a validation task, not a final finding:
  after product/version or dependency matching, launch focused validation with
  `cve_exploit_validation` and the relevant framework/technology skill.

**Blackbox (no source)**
- Exhaustive subdomain enumeration with multiple sources and tools
- Full port scanning across all services
- Complete content discovery with multiple wordlists
- Technology fingerprinting on all assets
- API discovery via docs, JavaScript analysis, fuzzing
- Identify all parameters including hidden and rarely-used ones
- Map all user roles with different account types
- Document rate limiting, WAF rules, security controls
- Document complete application architecture as understood from outside

After this mapping phase, load `portswigger_web_security_methodology` to build
the web/API vulnerability dispatch matrix. It routes every applicable Web
Security Academy family to the smallest matching specialist skill; do not load
the full catalog into every child agent.

Also load `hacktricks_recognition_and_validation` when the mapping reveals
source artifacts, identity systems, exposed services, cloud/Kubernetes/IaC,
CI/CD, directory infrastructure, or a proxy/CDN path. It supplies the
environmental recognition and pivot route, while the assigned specialist still
owns validation.

## Mandatory Product-Specific Hypothesis Discovery

After the normal skill dispatch, run a second hypothesis-discovery pass. The
existing skills are not an exhaustive permission list: infer bounded,
target-specific tests from the application's own trust boundaries and
invariants. For **every material high-value component**, create at least one
evidence-backed hypothesis or explicitly record why no meaningful one exists.

Load `hypothesis_driven_security_testing` and create a narrowly scoped
`Hypothesis Explorer` child with `role="hypothesis"` and a short name when a
hypothesis does not map cleanly to one existing vulnerability family. Good
sources are policy drift across UI/API/legacy/worker paths, expected controls
missing from a sensitive workflow, identity/routing/parser/cache representation
mismatches, and evidence-backed pivots between otherwise low-severity facts.
The child must state observed facts, protected invariant, attacker capability,
one minimal differential test, success condition, and stop condition before
testing. Set `testability` on every Thinking record and test `testable_now`
candidates first. Do not create a generic creativity task or run an unbounded
payload search.

Positive results still require independent validation; negative results must
name the control/invariant that held. A plausible path lacking a prerequisite
is recorded with `record_thinking` and its `testability`, never promoted to a
finding. Before finishing, call `get_creative_scorecard` and make sure the
creative layer produced testable work rather than only blocked notes.

## Deep CVE PoC Validation

In deep mode, CVE handling does not stop at detection. For every prioritized
candidate found through fingerprinting, advisory search, dependency scanning,
source review, scanner output, exposed product banners, or discovered
components:

- Confirm the exact product/component, affected version range, installed
  feature/plugin/configuration, attacker prerequisites, and target reachability.
- Research authoritative vendor/advisory sources first, then trusted PoCs or
  maintained exploit modules, and reduce any PoC to the smallest harmless check
  that proves the vulnerable condition.
- Delegate a focused child with `cve_exploit_validation` plus the relevant
  framework or technology skill. Quote the observed asset, endpoint, version,
  plugin/module, advisory URL, and scope constraints in the task.
- Execute only bounded, non-destructive PoC attempts: no persistence, data
  destruction, credential spraying, privilege escalation beyond the proof
  needed, lateral movement, or customer-data exfiltration.
- Close each CVE candidate explicitly as `confirmed`, `ruled_out`, or
  `inconclusive`. Store those outcomes as coverage `reported`, `ruled_out`, or
  `needs_follow_up` respectively; do not use `inconclusive` as a coverage value.
  A deep scan must not leave a CVE candidate as "detected only" without a
  validation outcome.
- When dynamically confirmed, file `create_vulnerability_report` with replayable
  evidence and HTTP exchange IDs when applicable. Dependency/SCA matches still
  keep their `create_dependency_report`; a dynamic proof becomes a linked
  normal vulnerability report, not a replacement for the dependency finding.

## Phase 2: Business Logic Deep Dive

Create a complete storyboard of the application:

- **User flows** - document every step of every workflow
- **State machines** - map all transitions (Created → Paid → Shipped → Delivered)
- **Trust boundaries** - identify where privilege changes hands
- **Invariants** - what rules should the application always enforce
- **Implicit assumptions** - what does the code assume that might be violated
- **Multi-step attack surfaces** - where can normal functionality be abused
- **Third-party integrations** - map all external service dependencies

Use the application extensively as every user type to understand the full data lifecycle.

## Phase 3: Comprehensive Attack Surface Testing

Test every input vector with every applicable technique.

### Bypass and Control-Plane Validation

- When recon finds a login, session, gateway, impersonation, alternate API, or
  partially authenticated state, dispatch `authentication_bypass` together
  with the relevant JWT/OAuth/SAML/MFA/session skill.
- When a WAF, CDN rule, bot challenge, API gateway, or block page is observed,
  dispatch `waf_evasion` and fingerprint the responding layer before testing
  bounded parser variants.
- When an allowlist, sanitizer, schema, canonicalizer, or content-type filter
  is present, dispatch `input_filter_bypass` plus the sink-specific skill.
- A bypass is reportable only when the variant reaches an unauthorized
  security consequence; an accepted request or different error alone is not a
  bypass. Record baseline/control and proving exchange IDs.

**Input Handling**
- Multiple injection types: SQL, NoSQL, LDAP, XPath, command, template
- Encoding bypasses: double encoding, unicode, null bytes
- Boundary conditions and type confusion
- Large payloads and buffer-related issues

**Authentication & Session**
- Exhaustive brute force protection testing
- Session fixation, hijacking, prediction
- JWT/token manipulation
- OAuth flow abuse scenarios
- Password reset vulnerabilities: token leakage, reuse, timing
- MFA bypass techniques
- Account enumeration through all channels

**Access Control**
- Test every endpoint for horizontal and vertical access control
- Parameter tampering on all object references
- Forced browsing to all discovered resources
- HTTP method tampering (GET vs POST vs PUT vs DELETE)
- Access control after session state changes (logout, role change)

**File Operations**
- Exhaustive file upload bypass: extension, content-type, magic bytes
- Path traversal on all file parameters
- SSRF through file inclusion
- XXE through all XML parsing points

**Business Logic**
- Race conditions on all state-changing operations
- Workflow bypass on every multi-step process
- Price/quantity manipulation in transactions
- Parallel execution attacks
- TOCTOU (time-of-check to time-of-use) vulnerabilities

**Advanced Techniques**
- HTTP request smuggling (multiple proxies/servers)
- Cache poisoning and cache deception
- Subdomain takeover
- Prototype pollution (JavaScript applications)
- CORS misconfiguration exploitation
- WebSocket security testing
- GraphQL-specific attacks (introspection, batching, nested queries)
- LLM/RAG/agent features: load `llm_applications` for OWASP 2026 LLM01-LLM10 coverage and `llm_prompt_injection` for deep injection testing

## Phase 4: Vulnerability Chaining

Individual bugs are starting points. Chain them for maximum impact:

- Combine information disclosure with access control bypass
- Chain SSRF to reach internal services
- Use low-severity findings to enable high-impact attacks
- Build multi-step attack paths that automated tools miss
- Cross component boundaries: user → admin, external → internal, read → write, single-tenant → cross-tenant

**Chaining Principles**
- Treat every finding as a pivot point: ask "what does this unlock next?"
- Continue until reaching maximum privilege / maximum data exposure / maximum control
- Prefer end-to-end exploit paths over isolated bugs: initial foothold → pivot → privilege gain → sensitive action/data
- Validate chains by executing the full sequence (proxy + browser for workflows, python for automation)
- When a pivot is found, spawn focused agents to continue the chain in the next component

## Phase 5: Persistent Testing

When initial attempts fail:

- Research technology-specific bypasses
- Try alternative exploitation techniques
- Test edge cases and unusual functionality
- Test with different client contexts
- Revisit areas with new information from other findings
- Consider timing-based and blind exploitation
- Look for logic flaws that require deep application understanding

## Phase 6: Comprehensive Reporting

- Document every confirmed vulnerability with full details
- Include all severity levels—low findings may enable chains
- Complete reproduction steps and working PoC
- Remediation recommendations with specific guidance
- Note areas requiring additional review beyond current scope

## Agent Strategy

After reconnaissance, decompose the application hierarchically:

Before vulnerability specialists begin, build a canonical host ledger from the
recon inventory. Every in-scope host/subdomain whose service is marked
`alive` must be named in a specialist assignment and receive a completed
handoff. The scan cannot finish while any live host is unassigned or held only
by a stopped specialist.

1. **Component level** - Auth System, Payment Gateway, User Profile, Admin Panel
2. **Feature level** - Login Form, Registration API, Password Reset
3. **Vulnerability level** - SQLi Agent, XSS Agent, Auth Bypass Agent

Spawn specialized agents at each level. Scale horizontally to maximum parallelization:
- Do NOT overload a single agent with multiple vulnerability types
- Each agent focuses on one specific area or vulnerability type
- Creates a massive parallel swarm covering every angle

## Mindset

Relentless. Creative. Patient. Thorough. Persistent.

This is about finding what others miss. Test every parameter, every endpoint, every edge case. If one approach fails, try ten more. Understand how components interact to find systemic issues.
