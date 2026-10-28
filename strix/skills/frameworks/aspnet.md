---
name: aspnet
description: ASP.NET and IIS security review for routing, identity, configuration, diagnostics, and deployment boundaries
---

# ASP.NET and IIS

## Surface

- MVC, Razor Pages, Web API, SignalR, minimal APIs, legacy Web Forms, and
  IIS-hosted static or diagnostic paths.
- Authentication middleware order, authorization policies, anti-forgery,
  forwarded headers, error handling, and environment-specific configuration.
- ViewState, machine keys, data-protection key storage, debug endpoints,
  trace/error handlers, and upload handlers.

## Review Method

Trace route registration through middleware to the handler and data sink. In
white-box review, identify whether secrets and cryptographic keys are unique,
protected, and rotated across deployments. In black-box testing, fingerprint
versions and features before researching advisories, then apply the known-CVE
gate rather than assuming version banners are exploitable.
