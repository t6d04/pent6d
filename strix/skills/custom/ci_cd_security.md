---
name: ci-cd-security
description: Source-aware CI/CD, build-pipeline, artifact, and workload-identity security review
---

# CI/CD Security

CI/CD pipelines execute privileged automation across source, dependencies,
secrets, artifacts, registries, and deployment identities. Review them as an
authorization graph, not just YAML syntax.

## Review Areas

- Trigger types, untrusted pull-request or branch inputs, reusable workflows,
  matrix values, and shell/template interpolation.
- Secret availability by event and environment, log masking, artifact access,
  cache keys, and provenance/attestation.
- Self-hosted runner isolation, cleanup, network reachability, and workspace
  reuse between jobs or repositories.
- OIDC/workload-identity claims, cloud trust policies, least privilege, and
  repository/environment binding.

## Validation

Prefer static dataflow and a benign test workflow in a dedicated repository.
Do not alter production pipelines, publish packages, invoke deployments, or
exfiltrate secrets to prove a finding. Record the exact trigger, trust boundary,
privilege granted, and the smallest safe reproduction.
