---
name: websocket
description: WebSocket and Socket.IO handshake, origin, message authorization, and channel-isolation testing
---

# WebSocket Security

WebSocket authorization must be enforced at the handshake and for each
subscription, room, topic, history query, and state-changing message. Treat a
socket as a protocol with its own authorization layer, not merely an HTTP route
that was checked once.

## Map

- Endpoint, subprotocol, origin handling, cookie/token authentication,
  compression/extensions, reconnect behaviour, and token refresh.
- Rooms, channels, tenant identifiers, message schemas, correlation IDs,
  binary frames, and client/server event names.
- Socket.IO or fallback polling transports, namespaces, upgrade flow, and
  transport-parity behaviour.
- Server-side authorization for subscribe, publish, history, presence,
  administrative controls, and indirect events triggered by a message.

## Controlled Identity Matrix

Use at least two controlled accounts where the target permits it: anonymous,
peer user, different tenant, and privileged user as applicable. Preserve each
cookie/token/browser profile independently. For each operation, compare:

```text
handshake → subscribe/join → history/read → publish/action → reconnect/replay
```

Vary one element at a time: socket token, room/object ID, namespace, event
name, message field, transport, or sequence number. Do not conclude that a
successful handshake authorizes later messages.

## Test Families

### Handshake and Cross-Site Initiation

- Check whether cookies/tokens are accepted on a hostile Origin and whether a
  browser can actually establish the connection under SameSite/CORS/browser
  constraints.
- Compare missing, malformed, expired, rotated, wrong-audience, and
  tenant-swapped tokens only with authorized test identities.
- Verify proxy/gateway and origin enforce the same authorization decision.

### Channel and Object Authorization

- Swap room, topic, tenant, user, document, and cursor identifiers in join,
  subscribe, history, and action messages.
- Test hidden namespaces and events inferred from JavaScript only when they
  are in scope. A verbose error or event acknowledgement is not proof without
  unauthorized data/action.
- Compare a forbidden operation with an allowed control request and capture
  the before/after authoritative state.

### Socket.IO / Transport Parity

- Compare WebSocket upgrade with polling/fallback paths; they must apply the
  same origin, session, tenant, and authorization rules.
- Inspect namespace joining, reconnect tokens, and event ordering. Do not rely
  on UI visibility: the protocol may expose admin events that the UI hides.

### Replay, Ordering, and Resource Boundaries

- Replay a controlled idempotent message, reorder a multi-step flow, and test
  reconnect behaviour for duplicated/expired authority.
- Bound tests for fan-out, compression, binary frames, and message size. These
  can become availability tests; do not use high volume or broad subscriptions
  without explicit authorization.

## Validation and Reporting

Capture a benign and proving handshake/message sequence through the proxy,
including the identity and resulting channel data or state change. A missing
Origin check matters only when browser credentials permit cross-site connection
and sensitive messages can be read or sent. Pair with `idor`,
`broken_function_level_authorization`, `csrf`, or `graphql` when the socket
operation shares that primary root cause.
