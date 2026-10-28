---
name: default_credentials
description: Evidence-led discovery and minimally invasive validation of documented default or bootstrap credentials
---

# Default and Bootstrap Credentials

Default credentials are a configuration finding, not a reason to run a broad
password attack. Work from a positively identified product, deployment method,
and version. A login that succeeds with a known vendor credential is reportable
only after you prove it is a real target account and record the authorization
scope and minimal HTTP evidence.

## Scope Gate

Before any active login attempt, confirm that the engagement permits
authentication testing on this exact host and service. If credential testing is
not explicitly in scope, do passive research only: fingerprint the service,
record the documented setup behaviour, and leave an `open_proof_gap` rather
than attempting to sign in.

- Start unauthenticated; do not test a login merely because an admin path was
  discovered.
- Do not use breach dumps, credential stuffing, password spraying, generic
  password lists, proxy rotation, CAPTCHA bypass, or lockout evasion under
  this skill. Those are separate, higher-impact activities requiring explicit
  authorization and a rate/lockout plan.
- Stop immediately on a CAPTCHA, 429, timeout pattern, lockout warning, or
  other anti-automation signal. Never retry to determine whether a lockout is
  real.

## Evidence-Led Research Workflow

1. **Fingerprint precisely.** Record product, edition, version, auth route,
   deployment method (package, container, Helm chart, appliance), and any
   first-run/setup state. A logo or a generic `/admin` route is not enough.
2. **Research live sources.** Use `web_search` for a product-and-version
   question such as `"<product> <version> official documentation default
   administrator credential first-run"`. Prefer the vendor's installation
   guide, release notes, container image docs, Helm values, and source
   configuration. Use `web_get_contents` when it is available to read the
   relevant official page; native OpenAI web search reads sources within the
   model tool instead.
3. **Classify the result.** Keep these cases separate:

   | Result | Active validation |
   |---|---|
   | Vendor-documented static default credential for this version | Eligible for one controlled attempt |
   | Installer-created, random, one-time, or environment-supplied bootstrap secret | Do not guess it; look only for a separate exposure/misconfiguration |
   | User-created administrator during setup | No default credential exists; do not try generic `admin` pairs |
   | Unverified blog/forum claim | Do not use it as a credential source; seek primary documentation |
4. **Create a tiny candidate set.** Keep only exact, version-matched,
   primary-source credentials. One documented pair per auth surface is the
   default cap; a second or third attempt needs distinct vendor evidence and
   stays within the engagement's agreed total request rate. Do not expand it
   into a wordlist or a username/password Cartesian product.
5. **Validate safely.** Capture a baseline failed/unauthenticated response,
   send the single permitted attempt, and confirm success from a session,
   authenticated identity endpoint, or harmless page that displays the role.
   Do not edit data, create users, rotate keys, launch jobs, or download
   sensitive records. Log out when possible.
6. **Preserve only necessary evidence.** Record product/version evidence,
   vendor source URL and access date, attempted username (redact the password
   in artifacts unless it is already a public vendor default), baseline and
   success HTTP exchange ids, and the least privilege/impact demonstrated.

## Product Facts That Prevent False Positives

Do not infer a universal `admin/admin` account from a technology name.

- **Django, Laravel, Rails, Spring Boot, ASP.NET, Express, FastAPI, Next.js,
  and NestJS** normally create no administrator with a framework-wide default
  password. Review source/deployment setup, seeded fixtures, `.env` files,
  and exposed setup routes instead.
- **WordPress, Drupal, Joomla, and Magento** normally collect administrator
  credentials during installation. Treat a claimed generic CMS default as
  unverified until the exact distribution/installer documentation says
  otherwise.
- **Jenkins** usually creates a per-install initial password; **Keycloak** and
  **Directus** bootstrap administrators from deployment configuration; **Strapi**
  creates an administrator during first-run setup. These are not invitations
  to guess values—test only a separately demonstrated secret exposure or a
  vendor-documented static default for the exact deployment.
- **Grafana** has historically documented `admin` / `admin` for a new local
  installation. Confirm the observed product and first-login state, then make
  no more than the single permitted attempt; anonymous access should be tested
  independently without credentials.

## Reporting Gate

Report only a confirmed authenticated session, the exact affected deployment,
and demonstrated least-privilege impact. The remediation is to require unique
installation-time credentials, disable or rotate bootstrap accounts, enforce
first-login password changes, and block public administrative access. A search
result, banner, or unsuccessful login is not a finding.
