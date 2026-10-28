---
name: cache-poisoning
description: Cache key, cache-control, and unkeyed-input analysis for web and API responses
---

# Cache Poisoning and Deception

Map the response path through browser, CDN, reverse proxy, and application
cache before testing. The core question is whether attacker-influenced input
changes a cacheable response without being represented in its cache key, or
whether cache and origin interpret a URL differently.

## Safety Boundary

- Use a controlled account and a unique harmless marker; do not poison shared
  login, payment, or production content for real users.
- Attach a unique cache buster to every trial so a prior response does not
  contaminate the oracle.
- Keep TTLs and request counts low. Persistent poisoning, cache eviction,
  victim delivery, and broad static-path enumeration need explicit engagement
  authorization.
- Distinguish a CDN-generated response, origin response, browser cache, and
  service-worker response before assigning root cause.

## Surface Map

- Cache headers, cache keys, `Vary`, surrogate keys, age/hit indicators, and
  redirects.
- Request components handled by proxies but absent from application routing:
  host-related headers, path normalization, forwarding headers, selected query
  parameters, content negotiation, and method handling.
- Differences between authenticated and anonymous responses, static-file and
  static-directory rules, error caching, and cache partitioning.
- Multi-hop infrastructure: browser → CDN/WAF → reverse proxy → origin. Load
  `http_request_smuggling` or `advanced_http_desync` when parser disagreement
  is plausible.

## Establish a Cache Oracle

1. Pick a safe GET/HEAD/OPTIONS endpoint and save the normal response as the
   baseline. Avoid state-changing routes.
2. Send the same request twice with a fresh unique cache-buster each time.
   Compare cache-related headers, response age, body, and timing.
3. Repeat from a clean profile/session where permitted. A response becoming
   faster is only a clue; retain header/body evidence too.
4. Record exactly which request components change the cache key. Vary one
   component at a time: path, query, host-related header, forwarding header,
   content type, language, or method.

## Cache Poisoning: Unkeyed Input

The candidate exists when a cacheable response changes based on attacker input
that is not represented in the cache key.

- Inventory URL generation, redirects, reflected headers, absolute links,
  JSON config, client bootstrap data, and error pages.
- Compare a baseline request with one harmless marker in a single candidate
  unkeyed component. Never combine many headers before identifying the
  influence source.
- Retrieve with a clean request that omits the marker but deliberately uses
  the same cache key. The marker must persist there to demonstrate sharing.
- Classify impact precisely: harmless reflection is a primitive; a reportable
  result needs a safe proof of a security-relevant redirect, script/data
  injection, policy bypass, or unauthorized response sharing.

## Cache Deception: Cache/Origin Path Differential

The candidate exists when origin returns sensitive dynamic content but the
cache regards the same path as static or otherwise cacheable.

1. Identify a controlled, authenticated endpoint that returns meaningful
   account-specific test data and supports a safe read method.
2. Determine how the origin handles appended path text and separators: compare
   a random suffix, a candidate delimiter plus suffix, and the original path.
3. Test whether a static extension, static-directory prefix, path parameter,
   encoded separator, or normalization difference changes cache treatment
   without changing the origin resource.
4. Use a controlled second account or clean context to confirm whether the
   response is shared. Never seek real-user data.

## False-Positive Controls

- A `Cache-Control` header alone does not prove a shared cache.
- A cache hit alone does not prove attacker input was unkeyed.
- Redirects, login expiry, personalization, A/B experiments, and service
  workers can produce different bodies without a vulnerability.
- Re-check after cache expiry and with a new cache key to rule out stale test
  artifacts.

## Reporting

Capture baseline, marker request, clean retrieval, cache-buster values, cache
headers/timing, principal context, and exact impact. Link related host-header,
XSS, request-smuggling, or desync reports rather than turning one root cause
into duplicate findings.
