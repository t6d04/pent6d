---
name: springboot
description: Spring Boot security review for actuator exposure, MVC/WebFlux routing, expression use, and configuration boundaries
---

# Spring Boot

## Surface

- MVC/WebFlux controllers, method security, error responses, validation,
  deserialization, file handling, template engines, and async messaging.
- Actuator endpoints, health details, environment/configuration exposure,
  metrics, mappings, heap dumps, loggers, and management-port separation.
- Expression evaluation, data binding, JMX, database query construction, and
  dependency-managed framework versions.

## Review Method

First identify which management endpoints are exposed and to whom. Separate
operational metadata from actual unauthorized access. For a suspected advisory,
verify product version, enabled feature, deployment configuration, and a
non-destructive proof. Use `exceptional_conditions` for fail-open parsers and
`dependency_cve_scanning` for library CVEs.
