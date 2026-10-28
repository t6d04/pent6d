---
name: second-order-sqli
description: Second-order SQL injection testing where stored input is interpreted as query syntax later in a separate workflow
---

# Second-Order SQL Injection

Second-order SQL injection occurs when an application safely accepts and
stores input at one boundary, then later incorporates that stored value into a
database query or dynamic identifier at another boundary. The vulnerable
request is often not the request that supplied the input.

## Where to Look

- Profile fields, display names, saved searches, filters, sort preferences,
  report definitions, import mappings, and tenant settings.
- Background jobs, exports, dashboards, support/admin views, audit search,
  notification templates, and cross-service synchronization.
- APIs that accept flexible JSON fields later reused as a query fragment,
  column name, or filter expression.

## Method

1. Map the producer endpoint, stored field, consumer endpoint or job, and
   database-facing sink.
2. Establish a harmless unique marker using an authorized test identity.
3. Trigger the later consumer with an otherwise identical baseline and observe
   errors, stable boolean differences, or a controlled timing signal.
4. Prove the producer-to-consumer linkage before escalating impact. A changed
   response at the producer alone is not evidence of second-order SQLi.
5. Preserve evidence for both phases and name the delay, queue, role, or
   state transition required for reproduction.

## Validation and Closure

Confirm that the stored value reaches a query context and that changing only
the relevant fragment changes the consumer behavior predictably. If a later
consumer is inaccessible or asynchronous, record `needs_follow_up` with the
missing trigger instead of declaring it safe.

For source review, trace the stored field through serialization, database
reads, and the final query builder. Parameterization at ingestion does not
protect a later raw-query construction.
