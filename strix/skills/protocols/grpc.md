---
name: grpc
description: gRPC and gRPC-Web endpoint inventory, transport, metadata, and authorization testing
---

# gRPC Security

gRPC services can expose methods through reflection, generated clients,
gRPC-Web gateways, or internal-looking HTTP/2 endpoints with inconsistent
authentication.

## Inventory

- Service and method names from reflection, proto files, SDKs, browser bundles,
  gateway routes, and proxy history.
- Transport security, TLS termination, gRPC-Web translation, streaming modes,
  deadlines, and metadata propagation.
- Authentication and authorization at gateway, service, and per-message layers.

## Validation

Use generated or approved test clients with controlled identities. Compare an
authorized and unauthorized call for one method/object. Reflection exposure
alone is reconnaissance; report it only when it discloses sensitive contracts
or enables a separate demonstrated weakness.
