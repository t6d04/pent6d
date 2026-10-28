---
name: advanced-http-desync
description: Modern HTTP desynchronization testing for CL.0, HTTP/2 downgrade/header quirks, browser-powered desync, and response-queue impact
---

# Advanced HTTP Desynchronization

Load this alongside `http_request_smuggling` only when reconnaissance shows a
multi-hop HTTP path, HTTP/2/HTTP/1.1 translation, connection reuse, a browser
delivery path, or a cache. It covers modern desync branches that should not be
attempted as generic high-volume probes.

## Preconditions and Safety

- Confirm explicit authorization for desync testing; malformed requests can
  interfere with shared back-end connections.
- Use a disposable controlled account, unique marker, low request count, and a
  bounded test endpoint. Do not target real users or broad traffic.
- Identify the front-end, protocol version, origin, connection reuse, and
  whether a cache/CDN/WAF sits on the route.
- Capture a normal request/control pair before every differential probe.

## Modern Candidate Families

### CL.0 / length-ignoring back ends

Some back ends ignore a body despite a front-end honoring its declared length.
Look for a reproducible difference between a normal request and a request with
a harmless trailing prefix, under a fresh controlled connection. Do not infer
desync from one timeout or generic 5xx; require repeatability and a parser
explanation.

### HTTP/2 translation and header rewriting

Where HTTP/2 is accepted at the edge but HTTP/1.1 reaches the origin, compare
normalized versus unusual header/body combinations. Focus on evidence that the
edge and origin disagree about boundaries or rejected headers. Treat HTTP/2
support itself as neither proof nor mitigation: the question is whether the
full chain preserves one unambiguous message boundary.

### Browser-powered and client-side desync

Only evaluate this family when a browser can make the relevant request shape
and connection reuse is plausible. Model browser constraints explicitly:

- same-origin versus cross-origin request ability;
- cookie/SameSite and CORS behaviour;
- cache partitioning and browser profile state;
- victim interaction, redirects, and resource import path.

Use a controlled browser profile and a benign marker. A raw-socket-only
desync does not establish a browser-powered issue.

### Response queue and connection-state impact

After confirming a controlled desync primitive, identify a bounded, harmless
follow-up request that demonstrates which request/response is affected. Then
consider only in-scope impacts: edge authorization bypass, internal-route
reachability, safe marker reflection, or controlled cache behaviour. Do not
attempt to receive another user's private response.

## Cache and Host-Header Pivots

Load `cache_poisoning` when the response can be cached and
`host_header_injection` when routing or URL generation consumes host-related
input. Demonstrate a clean independent retrieval of a harmless marker before
claiming a cache-based impact. Cache poisoning, cache deception, and response
queue effects are different primitives; name the one actually proven.

## Evidence and Closure

Report only with:

1. topology/protocol evidence;
2. normal baseline and repeatable differential;
3. parser-boundary explanation;
4. bounded security consequence; and
5. exact proving proxy exchanges.

If only a suspicious timeout or one-off error exists, record a Thinking item
with the missing controlled validation step. Do not label a connection anomaly
as request smuggling without a demonstrated desynchronization effect.
