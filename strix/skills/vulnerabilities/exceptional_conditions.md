---
name: exceptional-conditions
description: Fail-open behavior, unsafe error handling, and parser-boundary testing with malformed but bounded inputs
---

# Exceptional Conditions

Exceptional inputs reveal whether validation, authorization, and cleanup remain
correct when parsers, downstream services, or optional fields fail.

## Inputs to Vary

- Missing, null, duplicate, oversized-within-policy, and wrong-type fields.
- Broken JSON/XML, unexpected encodings, empty collections, and malformed
  pagination or sort values.
- Upstream timeouts, partial uploads, retry paths, and asynchronous failure
  states where a request can be replayed or finalized twice.

## What Counts

Look for fail-open authorization, unsafe default objects, information leakage,
inconsistent validation across parsers, and state changes after a reported
failure. A verbose error is not automatically high severity; prove that it
reveals restricted information or bypasses a control. Keep malformed inputs
bounded and do not use resource-exhaustion tests without authorization.
