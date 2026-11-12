# Pent6d

Pent6d is a self-hosted, agent-driven security testing platform for authorized
web applications, APIs, source trees, and infrastructure. It combines
reconnaissance, specialized vulnerability testing, evidence collection,
exploit validation, impact chaining, and report generation in one local
workflow.

The project is designed for teams that want full control over targets, model
credentials, scan artifacts, and deployment. The runtime, browser hub, and
agent state can all run on infrastructure that you manage.

> **Authorized use only.** Test only systems that you own or have explicit,
> written permission to assess. Keep every target inside the agreed scope.

## Capabilities

- Agent-driven orchestration with dedicated recon, testing, validation, and
  reporting roles.
- Browser-first project and run management, including live progress, thinking
  events, chat, findings, recon evidence, workflow state, and exports.
- Black-box, grey-box, API, white-box, and firmware/reverse-engineering
  workflows where the required evidence and tooling are available.
- Recon evidence for subdomains, active services, screenshots, forms, POST
  inputs, JavaScript/source leaks, fingerprints, and other attack-surface data.
- Checklist-guided coverage plus creative hypothesis generation. Unproven
  hypotheses are recorded separately from validated findings.
- Shared memory across agents in the same run, chain/impact review after
  testing, and resumable run state.
- Markdown and PDF report export for the overview and individual findings.
- Optional MCP and sidecar integrations for additional security tooling.

## Requirements

- Python 3.12 or newer.
- Docker running locally or on the host that executes the scan.
- An LLM provider and credentials configured for your deployment.
- Network access to authorized targets when performing live testing.

## Installation

```bash
git clone https://github.com/t6d04/pent6d.git
cd pent6d
uv sync
```

The first scan may download the sandbox image and initialize the local run
store.

## Browser-first workflow

Start the local web hub:

```bash
uv run pent6d web
```

Open the printed URL, create or select a project, configure the model, and
add authorized targets in **New Run**. Each project has its own scope,
settings, run history, findings, recon data, and chat context.

To access the hub from a trusted LAN, bind it explicitly and restrict clients
to the smallest required network range:

```bash
uv run pent6d web \
  --host 0.0.0.0 \
  --port 8081 \
  --allow-network 192.168.16.0/24
```

`--allow-network` controls which browser clients may reach the hub; it is not
a substitute for authentication. Keep the tokened URL private. For networks
you do not fully trust, use an HTTPS reverse proxy or an SSH tunnel instead of
exposing the hub directly.

### Project and run lifecycle

1. Create a project for one authorized engagement or product.
2. Add one or more targets in **New Run**. Multiline, comma-separated, and
   semicolon-separated input is parsed into separate targets.
3. Start the run. Recon completes first and writes shared evidence for the
   testing agents.
4. Vulnerability specialists are scheduled for every authorized host or
   subdomain whose service is active, not only a manually selected subset.
5. The chain/impact pass reviews related findings and upgrades their combined
   impact where the evidence supports it.
6. Review findings, informational observations, and hypotheses in **Overview**;
   continue the conversation in the run-specific chat.
7. Export the overview or an individual finding as Markdown or PDF.

The run overview exposes agent activity and thinking events so a long-running
scan is distinguishable from a stalled or failed scan. A run can be continued
from the UI when it was interrupted or failed recoverably and its state files
are still present. Continuation reuses the existing run and artifacts.

## Recon coverage

Recon data is persisted with the run and can be revisited from the Recon tab.
Depending on target and scan mode, Pent6d records:

- discovered domains and subdomains;
- active-service checks and screenshots for alive web services;
- HTTP status, title, technology, and endpoint observations;
- forms, methods, content types, field names, and POST bodies;
- JavaScript files, source-leak references, and downloaded local source paths;
- API specifications, fingerprints, exposed services, and other evidence used
  to select follow-up tests.

An **alive** host is treated as an active service only after a service-level
response is observed; DNS resolution alone is not sufficient. Recon evidence
is placed into shared run memory before specialists begin their work.

## CLI usage

Run from the checkout:

```bash
# Local source review
uv run pent6d --target ./app-directory

# Live web application assessment
uv run pent6d --target https://your-app.example

# Multiple targets
uv run pent6d -t https://api.example -t ./openapi.yaml

# Headless execution for automation
uv run pent6d -n --target https://your-app.example
```

The installed executable can be used instead of `uv run pent6d` when the
environment has been provisioned:

```bash
pent6d --target ./app-directory
```

Use `--resume <run-name>` to continue a saved headless run. Always inspect the
resulting run status and evidence before treating a scan as clean.

## Model, retry, and rate-limit settings

The browser setup form supports the model route, API base, API key, custom
request headers, request rate limits, and transient-error retry attempts.
Rate limits can be expressed in seconds, minutes, or hours. Custom headers are
sent to the model provider on every request, so treat them as secret-bearing
configuration and do not share them with other projects.

For headless or CI execution, configure the same values through the model
environment/configuration supported by your deployment before starting the
process. Keep credentials in the CI secret store or a local secret file that
is excluded from version control.

## CI usage

Pent6d can run in a CI job after Docker and model credentials are available:

```yaml
name: pent6d-security-scan

on:
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install dependencies
        run: |
          curl -LsSf https://astral.sh/uv/install.sh | sh
          uv sync

      - name: Run Pent6d
        run: uv run pent6d -n -t ./ --scan-mode quick
```

Keep credentials in repository or organization secrets and restrict CI scope
to approved staging environments or source snapshots.

## Development

```bash
make dev-install
uv run pytest
make check-all
```

The main areas are:

- **Agent graph** — orchestration, prompts, roles, and shared state;
- **Skills** — internal security knowledge packs;
- **Tooling** — browser, proxy, terminal, scanner, MCP, and connector tools;
- **Interface** — CLI, web hub, backend controller, and viewer frontend;
- **Reporting** — findings, coverage, exports, and SARIF output;
- **Sandbox** — container image and runtime configuration.

## License and responsible use

See [LICENSE](LICENSE) for licensing terms. Pent6d is provided without a
warranty. You are responsible for authorization, scope control, safe rate
limits, handling credentials, and complying with applicable law.
