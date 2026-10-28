# 📚 Strix Skills

## 🎯 Overview

Skills are specialized knowledge packages that enhance Strix agents with deep expertise in specific vulnerability types, technologies, and testing methodologies. Each skill provides advanced techniques, practical examples, and validation methods that go beyond baseline security knowledge.

---

## 🏗️ Architecture

### How Skills Work

When an agent is created, it can load up to 5 specialized skills relevant to the specific subtask and context at hand:

```python
# Agent creation with specialized skills
create_agent(
    task="Test authentication mechanisms in API",
    name="Auth Specialist",
    skills="authentication_jwt,business_logic"
)
```

The skills are dynamically injected into the agent's system prompt, allowing it to operate with deep expertise tailored to the specific vulnerability types or technologies required for the task at hand.

---

## 📁 Skill Categories

| Category | Purpose |
|----------|---------|
| **`/vulnerabilities`** | Advanced testing techniques for core vulnerability classes like authentication bypasses, business logic flaws, and race conditions |
| **`/frameworks`** | Specific testing methods for popular frameworks e.g. Django, Express, FastAPI, and Next.js |
| **`/technologies`** | Specialized techniques for third-party services such as Supabase, Firebase, Auth0, and payment gateways |
| **`/protocols`** | Protocol-specific testing patterns for GraphQL, WebSocket, OAuth, and other communication standards |
| **`/tooling`** | Command-line playbooks for core sandbox tools (nmap, nuclei, httpx, ffuf, subfinder, naabu, katana, sqlmap) |
| **`/cloud`** | Cloud provider security testing for AWS, Azure, GCP, and Kubernetes environments |
| **`/reconnaissance`** | Advanced information gathering and enumeration techniques for comprehensive attack surface mapping |
| **`/custom`** | Community-contributed skills for specialized or industry-specific testing scenarios |

Notable source-aware skills:
- `source_aware_whitebox` (coordination): white-box orchestration playbook
- `verified_whitebox_audit` (coordination): evidence-gated white-box audit protocol with fresh verifiers and coverage critics
- `source_aware_sast` (custom): semgrep/AST/secrets/supply-chain static triage workflow
- `dependency_cve_scanning` (custom): trivy-based SCA workflow for reporting known dependency CVEs via `create_dependency_report`
- `npx_confusion` (custom): npx/npm exec/bunx fallback and adjacent package-runner identity confusion, with runner-specific registry and reporting gates
- `semantic_confusion` (vulnerabilities): cross-boundary parser, normalization, and representation mismatch analysis
- `agentic_system_security` (vulnerabilities): effective-authority and MCP/tool ecosystem security testing
- `browser_security` (vulnerabilities): browsing-context, postMessage, XS-Leaks, service-worker, and cross-origin state-machine testing
- `second_order_sqli` (vulnerabilities): deferred SQL query construction through stored fields and later consumers
- `shadow_api` (vulnerabilities): undocumented, legacy, client-inferred, and version-drift API surfaces
- `scope_triage` (reconnaissance): authorization-aware handling of discovered hosts and routes before active testing
- `web_attack_surface` (reconnaissance): historical URLs, hidden parameters, JavaScript, sensitive files, visual triage, and scope-aware web attack-surface handoff
- `recon_enrichment` (tooling): bounded command patterns for passive-source enrichment, DNS permutation, URL history, parameter mining, and JS triage
- `triage_validation` (analysis): evidence-first reportability gate for candidates and known CVEs
- `evidence_hygiene` (analysis): redaction and minimum-evidence handling for reports and artifacts
- `default_credentials` (vulnerabilities): product/version-specific vendor research and bounded validation of documented default or bootstrap credentials
- `cve_exploit_validation` (vulnerabilities): deep-mode closure of CVE candidates with bounded PoC validation and explicit confirmed/ruled-out/inconclusive outcomes
- `authentication_bypass` (vulnerabilities): local, session, gateway, and alternate-route authentication-boundary testing
- `waf_evasion` (vulnerabilities): controlled WAF fingerprinting and parser-differential validation
- `input_filter_bypass` (vulnerabilities): canonicalization and parser/validation-boundary differential testing

Additional external-application coverage added as independently maintained
skills includes `account_takeover`, `api_misconfiguration`, `cache_poisoning`,
`clickjacking`, `cors_misconfiguration`, `exceptional_conditions`,
`forgot_password`, `host_header_injection`, `html_injection`,
`ldap_xpath_injection`, `mfa_bypass`, and `session_management`; gRPC, SAML,
and WebSocket protocol coverage; ASP.NET, Laravel, Node.js, and Spring Boot
framework guidance; and source-aware `ci_cd_security` review.

See [`docs/claude_bughunter_skill_mapping.md`](../../docs/claude_bughunter_skill_mapping.md)
for the coverage map for the independently adapted Claude-BugHunter categories.
- `azure` (cloud): Azure and Microsoft Entra privilege, PIM, workload identity, and cross-plane escalation analysis
- `infrastructure_lifecycle` (reconnaissance): abandoned or mutable external dependencies such as update endpoints, MX, storage, and control domains
- `argument_injection` (vulnerabilities): shell-free CLI option smuggling, secondary argument-file parsing, and platform-specific argv transformation boundaries
- `electron_desktop_apps` (technologies): Electron renderer-to-native trust boundaries, preload/IPC exposure, and navigation analysis
- `portswigger_web_security_methodology` (custom): evidence-first routing
  across the full PortSwigger Web Security Academy web/API taxonomy; loaded
  after recon to build specialist dispatch matrices without bloating every
  agent's context
- `hacktricks_recognition_and_validation` (custom): HackTricks-inspired
  environment, identity, infrastructure, cloud, CI/CD, and protocol signal
  recognition; loaded after recon to route bounded validation to the right
  specialist without preloading a payload catalogue
- `hypothesis_driven_security_testing` (custom): evidence-led investigation
  of product-specific invariants, policy drift, negative-space controls, and
  novel trust-boundary hypotheses beyond the predefined vulnerability taxonomy
- `advanced_http_desync` (vulnerabilities): bounded validation of CL.0,
  HTTP/2 translation quirks, browser-powered/client-side desync, and
  response-queue impact

Notable LLM security skills:
- `llm_applications` (technologies): end-to-end OWASP 2026 LLM01-LLM10 coverage across models, RAG, vectors, agents, tools, outputs, supply chain, and resource controls
- `llm_prompt_injection` (vulnerabilities): deep direct, indirect, multimodal, memory, and tool-result prompt-injection testing

---

## 🎨 Creating New Skills

### What Should a Skill Contain?

A good skill is a structured knowledge package that typically includes:

- **Advanced techniques** - Non-obvious methods specific to the task and domain
- **Practical examples** - Working payloads, commands, or test cases with variations
- **Validation methods** - How to confirm findings and avoid false positives
- **Context-specific insights** - Environment and version nuances, configuration-dependent behavior, and edge cases
- **YAML frontmatter** - `name` and `description` fields for skill metadata

Skills focus on deep, specialized knowledge to significantly enhance agent capabilities. They are dynamically injected into agent context when needed.

---

## 🤝 Contributing

Community contributions are more than welcome — contribute new skills via [pull requests](https://github.com/usestrix/strix/pulls) or [GitHub issues](https://github.com/usestrix/strix/issues) to help expand the collection and improve extensibility for Strix agents.

---

> [!NOTE]
> **Work in Progress** - We're actively expanding the skills collection with specialized techniques and new categories.
