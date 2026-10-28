# Claude-BugHunter coverage mapping

This document records how Strix maps the public vulnerability categories in
Claude-BugHunter to independently maintained Strix skills. It is a coverage
map, not a content import. See [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)
for attribution.

| Claude-BugHunter category | Strix coverage |
| --- | --- |
| API misconfig, shadow API, SPA API | `api_misconfiguration`, `shadow_api`, `spa_api_discovery`, `mass_assignment` |
| ATO, auth bypass, recovery, MFA, session, brute-force/CAPTCHA | `account_takeover`, `forgot_password`, `mfa_bypass`, `session_management`, `anti_automation_controls`, `authentication_jwt`, `weak_password_detection` |
| Cache, CORS, clickjacking, DOM/HTML | `cache_poisoning`, `cors_misconfiguration`, `clickjacking`, `html_injection`, `browser_security`, `xss` |
| SQL/NoSQL/LDAP/path/file input | `sql_injection`, `second_order_sqli`, `nosql_injection`, `ldap_xpath_injection`, `path_traversal_lfi_rfi`, `insecure_file_uploads` |
| GraphQL, gRPC, SAML, OAuth, WebSocket | `graphql`, `grpc`, `saml`, `oauth`, `websocket` |
| Source leaks and exceptional behavior | `source_artifact_leakage`, `information_disclosure`, `exceptional_conditions` |
| CI/CD and supply chain | `ci_cd_security`, `dependency_cve_scanning`, `npx_confusion`, `source_aware_sast` |
| Framework/platform-specific | `aspnet`, `django`, `fastapi`, `laravel`, `nextjs`, `nestjs`, `nodejs`, `springboot`, cloud and technology skills |

Enterprise appliance, post-credential, mobile, and Web3 chains are deliberately
not imported as default automated scan knowledge. They need an explicit target
type, scope, and operator-approved engagement mode.
