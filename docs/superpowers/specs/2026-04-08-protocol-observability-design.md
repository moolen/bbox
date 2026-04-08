# Protocol Observability Design

## Goal

Improve bbox observability for non-HTTP traffic without changing policy semantics or breaking existing access-log consumers. The system should continue to fail closed for unsupported opaque TCP traffic, but it should classify well-known protocols when possible and surface that information as additive log metadata.

## Current Behavior

### Proxy mode

- bbox injects `HTTP_PROXY` and `HTTPS_PROXY`.
- Plain HTTP requests become `Kind=http`.
- HTTP `CONNECT` tunnels become `Kind=connect`.
- If MITM is enabled, decrypted HTTPS requests become `Kind=mitm`.
- Proxy mode does not provide a generic transport for arbitrary raw TCP protocols unless the client explicitly supports an HTTP proxy or CONNECT tunnel.

### Transparent mode

- Seccomp redirection and the transparent ingress path intercept TCP and DNS.
- Transparent TCP sniffing currently recognizes:
  - HTTP/1 requests
  - cleartext HTTP/2 preface (`h2c`)
  - TLS ClientHello
- Recognized HTTP and HTTPS traffic is then handled by the existing HTTP or MITM paths.
- Opaque TCP that does not look like HTTP or TLS is reset and currently does not emit a protocol-specific structured access-log classification.

## Problem Statement

Two gaps remain:

1. bbox does not make it easy to explain why a non-HTTP protocol failed in transparent mode. For example, a MySQL or Redis client currently fails closed but the structured access log only shows a connect-style event, not the likely application protocol.
2. bbox has no explicit protocol-level coverage for gRPC and no fail-closed integration coverage for a concrete opaque TCP protocol such as MySQL.

The goal is observability, not protocol support. Unsupported protocols should continue to fail closed.

## Non-Goals

- No policy-language changes
- No protocol-specific allow/deny rules
- No routing changes for opaque protocols
- No attempt to support arbitrary non-HTTP application protocols in proxy or transparent mode
- No top-level `Kind` changes that would break existing consumers of `connect`, `transparent_connect`, `http`, `mitm`, or `dns`

## Recommended Approach

Keep existing `Kind` values and add protocol metadata alongside them.

### Additive metadata

Add optional protocol-observability fields to structured access events and log entries:

- `Protocol`
- `ProtocolSource`
- `ProtocolConfidence`

Initial semantics:

- `Protocol` is a normalized protocol label such as `grpc`, `mysql`, `postgres`, `redis`, `ssh`, `http`, `https`, `tls_non_http`, or `unknown`.
- `ProtocolSource` records how bbox inferred the protocol, such as `http_headers`, `http_connect`, `tls_alpn`, `tls_client_hello`, or `first_bytes`.
- `ProtocolConfidence` records inference strength, initially `definite`, `probable`, or `unknown`.

These fields must be optional and omitted when bbox genuinely has no useful signal.

### Logging model

- Preserve existing `Kind` values.
- Populate protocol metadata on the same access event whenever bbox can infer it.
- Continue to aggregate host/request data using the existing request shape and `Kind`.
- If later desired, summaries can grow protocol-aware fields in a separate change. This feature only requires structured access logs to carry the new metadata.

## Protocol Detection Matrix

### Proxy mode

#### Plain HTTP

- `Kind=http`
- `Protocol=http`
- `ProtocolSource=http_headers`
- `ProtocolConfidence=definite`

#### CONNECT tunnel without MITM

- `Kind=connect`
- Preserve current behavior.
- Do not add speculative protocol labels for raw tunnels unless there is a concrete signal.
- If bbox later sees explicit CONNECT metadata that is strong enough to classify, that can be added, but this change does not require generic CONNECT protocol guessing.

#### MITM HTTPS

- `Kind=mitm`
- `Protocol=https` by default
- If the decrypted request is HTTP/2 and carries gRPC content semantics, classify as:
  - `Protocol=grpc`
  - `ProtocolSource=http_headers`
  - `ProtocolConfidence=definite`

The initial gRPC heuristic should use decrypted HTTP request data that bbox already has:

- HTTP/2 or `ProtoMajor == 2`
- `content-type` starts with `application/grpc`

### Transparent mode

#### Recognized HTTP

- `Kind=transparent_connect` for the authorization event and existing HTTP/MITM events after interception.
- The authorization event may carry `Protocol=http` or `Protocol=https` when transparent sniffing identifies the class.

#### Opaque TCP

Before fail-closed reset, inspect the buffered initial bytes and classify common protocols when possible.

Initial protocol set:

- `mysql`
  - Match common server greeting shape: 3-byte payload length + sequence byte + protocol version `0x0a`
- `postgres`
  - Match SSLRequest / StartupMessage prefixes and lengths
- `redis`
  - Match RESP lead bytes such as `*`, `+`, `-`, `:`, `$`
- `ssh`
  - Match `SSH-`
- `tls_non_http`
  - Match TLS ClientHello where the intercepted flow does not proceed through the HTTP/TLS MITM path as HTTP
- `unknown`
  - Fallback when bbox has bytes but no classifier matches

Opaque traffic must still be denied. The new behavior is only improved attribution in logs.

## Technical Design

### 1. Shared protocol metadata shape

Extend `accessEvent` and `AccessLogEntry` with optional protocol metadata fields.

This keeps the external shape stable while allowing new visibility for both integration tests and CLI JSON logs.

### 2. Transparent opaque TCP classifier

Add a focused classifier for non-HTTP transparent TCP sniffing:

- Input: buffered prefix bytes captured during transparent TCP protocol detection
- Output: `(protocol, source, confidence)`

The classifier should be isolated in a small helper rather than embedded into the main ingress switch. This makes it easy to add tests and extend signatures later.

### 3. Transparent logging path

When `ServeTransparentTCPConn` classifies the stream as `unknown` from the perspective of HTTP/TLS routing, it should:

- derive protocol metadata from the buffered bytes
- emit a connect-style audit event with `Kind=transparent_connect`
- mark it denied when enforcement denies the underlying transparent connect
- then close the socket as today

If the existing connect authorization path already logs the `transparent_connect` event, the implementation should enrich that event instead of creating a duplicate.

### 4. MITM gRPC classification

In the MITM request path, inspect the decrypted request headers and protocol version:

- If it is HTTP/2 and the content type indicates gRPC, set `Protocol=grpc`
- Otherwise set `Protocol=https`

This should happen in the request-to-access-event construction path, not in transport code.

### 5. No summary-schema expansion in this change

Keep request aggregates and accessed-domain summaries backward-compatible for now. They already aggregate by `Kind`, `Host`, `Port`, `Method`, and `Path`. Introducing protocol aggregation is useful, but it is not required to satisfy the observability goal and would enlarge the change surface unnecessarily.

## Testing Strategy

### Unit tests

Add deterministic unit tests for the protocol classifier:

- MySQL handshake prefix -> `mysql`
- PostgreSQL startup / SSL request -> `postgres`
- Redis RESP prefix -> `redis`
- SSH banner -> `ssh`
- unknown opaque bytes -> `unknown`

Add log-shape tests to confirm the new additive fields:

- Existing `Kind` values remain unchanged
- New protocol fields are populated where expected
- Existing access summaries still work

### Integration tests

Add new integration coverage:

1. gRPC over MITM / HTTP2
   - Synthetic gRPC server/client
   - Verify request succeeds
   - Verify access log metadata records `Protocol=grpc`

2. MySQL-like opaque TCP in transparent mode
   - Synthetic server sends a MySQL-style greeting or client sends a MySQL-like initial packet
   - Verify sandbox client fails closed
   - Verify structured access log records `Kind=transparent_connect` plus `Protocol=mysql`

3. Existing transparent HTTP/HTTPS tests remain unchanged and continue to prove current supported flows.

## Risks and Mitigations

### Risk: false-positive classification

Opaque binary protocols can overlap in first-byte signatures.

Mitigation:

- keep the initial classifier conservative
- prefer `probable` confidence where patterns are heuristic
- use `unknown` instead of over-classifying

### Risk: duplicate access events

If transparent authorization and opaque protocol detection each emit their own event, logs may double-count a single failed connection.

Mitigation:

- enrich the existing transparent connect event rather than adding a second event
- add regression tests that assert a single denied transparent connect entry

### Risk: accidental behavior change

Protocol detection must not alter allow/deny decisions.

Mitigation:

- keep classifier side-effect free
- apply it only when constructing access metadata
- retain existing close/reset behavior for unsupported protocols

## Rollout Order

1. Add additive protocol metadata fields and JSON coverage tests
2. Add failing unit tests for protocol classification
3. Add failing transparent integration test for MySQL-style opaque TCP
4. Implement classifier and transparent logging enrichment
5. Add failing gRPC integration test
6. Implement MITM gRPC classification
7. Run targeted and full test suites

## Expected Outcome

After this change:

- unsupported non-HTTP traffic still fails closed
- bbox logs reveal likely protocol identity for well-known opaque TCP handshakes
- gRPC has explicit regression coverage
- MySQL-style opaque TCP has explicit fail-closed coverage
- existing access-log consumers continue to work because `Kind` values remain stable
