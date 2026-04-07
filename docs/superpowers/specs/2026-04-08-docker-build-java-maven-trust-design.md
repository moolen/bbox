# Docker Build Java And Maven Proxy/Trust Design

## Goal

Extend the existing rootless `docker build` support so proxy mode also works for:

- raw JDK HTTPS networking
- Maven dependency resolution

without weakening bbox's network boundary.

The build must continue to run inside the existing bbox sandbox, remain rootless, and keep fail-closed semantics for clients that do not honor the supported proxy/trust injection model.

## Current State

The current docker-build shim already does three important things:

- runs `buildkitd` and `buildctl` inside the sandbox
- forwards standard proxy env as Docker build args
- rewrites Dockerfiles to inject a staged trust bundle before every `RUN`

That trust injection currently targets Linux/OpenSSL and Node clients by copying a PEM bundle into common CA locations and setting:

- `SSL_CERT_FILE`
- `NODE_EXTRA_CA_CERTS`
- `NPM_CONFIG_CAFILE`

The synthetic integration fixture currently covers:

- `curl`
- `wget`
- `npm`
- `pip`
- `go mod download`

Java and Maven are not yet covered.

## Requirements

### Functional

- proxy-mode `docker build` must support raw JDK HTTPS requests in Dockerfile `RUN` steps
- proxy-mode `docker build` must support Maven dependency resolution in Dockerfile `RUN` steps
- transparent mode behavior must continue to work unchanged
- non-proxy-aware clients must continue to fail closed in proxy mode
- support must remain multi-stage-safe

### Compatibility

- trust injection should be automatic and not require edits to user Dockerfiles
- Java trust must work even when the base image does not import the MITM CA into a system JVM truststore by itself
- Maven proxying must not depend on undocumented behavior such as hoping Maven consumes `HTTP_PROXY` directly

### Verification

- unit tests must cover the expanded Dockerfile rewrite and generated assets
- the default synthetic docker-build integration must cover raw JDK networking and Maven dependency resolution
- the proxy-mode negative test must remain in place

## Recommended Approach

Keep the existing bbox sandbox plus rootless BuildKit architecture and extend the docker-build shim's staging layer.

This work should stay within the current `internal/dockerbuild` pipeline:

1. resolve and stage trust assets before the build starts
2. rewrite the Dockerfile to inject those assets before every `RUN`
3. continue passing proxy env into the build in proxy mode
4. add Java- and Maven-specific configuration artifacts where PEM env injection alone is insufficient

This keeps bbox as the only network policy engine. It also avoids inventing a second sandbox or builder-specific network path.

## Design

### 1. Expand PEM-based trust env injection

The existing trust snippet should be extended to export the staged PEM bundle for more clients that already support direct CA-bundle env overrides.

Add:

- `CURL_CA_BUNDLE`
- `REQUESTS_CA_BUNDLE`
- `PIP_CERT`
- `GIT_SSL_CAINFO`

Keep:

- `SSL_CERT_FILE`
- `NODE_EXTRA_CA_CERTS`
- `NPM_CONFIG_CAFILE`

Do not add `GIT_SSL_CAPATH` in this change. It expects a hashed certificate directory rather than a single PEM file, which would require a different artifact generation path and more image-level assumptions.

### 2. Generate and stage a JVM truststore

PEM env injection is not sufficient for the JVM. The shim should therefore generate a Java truststore from the resolved MITM PEM bundle and stage it alongside the rewritten Dockerfile.

The staged asset should be treated exactly like the PEM bundle:

- copied into the image before every `RUN`
- referenced through injected env or JVM properties
- cleaned up when the build finishes

The truststore format should be `PKCS12`, generated directly by bbox in Go rather than shelling out to host-side Java tooling. This keeps the feature self-contained and avoids adding a host prerequisite such as `keytool`.

### 3. Inject JVM trust and proxy properties

Raw JDK networking should be supported through injected JVM properties.

The rewrite snippet should set `JAVA_TOOL_OPTIONS` so Java-based commands run during `RUN` steps automatically inherit:

- `-Djavax.net.ssl.trustStore=<staged path>`
- `-Djavax.net.ssl.trustStoreType=<format>`
- `-Djavax.net.ssl.trustStorePassword=<generated password>`
- `-Dhttp.proxyHost=<host>`
- `-Dhttp.proxyPort=<port>`
- `-Dhttps.proxyHost=<host>`
- `-Dhttps.proxyPort=<port>`

If `NO_PROXY` is present, translate the supported subset into `-Dhttp.nonProxyHosts=...`.

This translation is necessarily best-effort because Java's `http.nonProxyHosts` syntax does not match general `NO_PROXY` syntax one-to-one. The implementation should document that only simple host patterns are normalized. Unsupported `NO_PROXY` entries should be omitted rather than guessed.

When proxy env is absent, no JVM proxy properties should be injected.

### 4. Generate Maven `settings.xml`

Maven proxy support should be explicit rather than inferred from Java runtime behavior alone.

The shim should generate a `settings.xml` file in the staged trust context when proxy env is present, with:

- an active `<proxy>` entry for HTTP/HTTPS traffic
- a `nonProxyHosts` value when it can be derived safely from `NO_PROXY`

The rewrite snippet should set `MAVEN_ARGS=-s <staged settings path>` so `mvn` uses that generated configuration during every `RUN` without requiring Dockerfile edits.

Maven should still inherit the JVM truststore configuration from `JAVA_TOOL_OPTIONS` so TLS trust and proxy routing stay aligned.

### 5. Preserve fail-closed semantics

No transparent fallback should be added to proxy mode.

Success in proxy mode should continue to mean:

- the client honored the injected proxy configuration
- the client trusted the injected MITM CA material
- bbox policy allowed the proxied egress

Clients that ignore the supported proxy configuration should still fail.

## Synthetic Integration Design

Replace the old Spectre-shaped default validation with a richer synthetic fixture.

The generated Dockerfile should include stages for:

- `curl`
- `wget`
- `node`
- `python`
- `go`
- raw JDK networking
- Maven dependency resolution
- a final multi-stage verification stage

The Java stage should perform a real HTTPS fetch using standard JDK APIs with no image-local trust customization beyond what bbox injects.

The Maven stage should resolve a small public dependency using `mvn` and write a deterministic artifact or dependency listing into `/out`.

The final stage should copy outputs from every prior stage and assert they exist. This proves the injected configuration works across all stages in one build graph.

## Testing Strategy

### Unit tests

Add focused tests around:

- expanded trust env injection
- staging of the Java truststore artifact
- JVM proxy/trust property synthesis from proxy env
- Maven settings generation
- `NO_PROXY` to Java/Maven non-proxy translation behavior

### Integration tests

Keep:

- proxy-mode positive matrix build
- transparent-mode positive matrix build
- proxy-mode negative fail-closed build

Extend the positive matrix so it exercises:

- raw JDK HTTPS networking
- Maven dependency resolution

The network allowlist will need the minimum additional Maven Central hosts required by the fixture.

## Limitations

- Java `http.nonProxyHosts` does not fully express all `NO_PROXY` forms
- some Java tools outside raw JDK networking and Maven may need their own config paths later
- `GIT_SSL_CAPATH` support is intentionally deferred
- automatic Maven proxy injection in this design targets Maven versions that support `MAVEN_ARGS`

These are acceptable for this change because they do not weaken policy enforcement and they keep the initial support surface explicit.

## Acceptance Criteria

The work is complete when:

- proxy-mode synthetic docker builds pass for curl, wget, npm, pip, go, raw JDK networking, and Maven
- transparent-mode synthetic docker builds still pass
- the non-proxy-aware negative docker-build integration still fails closed
- unit tests cover the generated trust/proxy artifacts and rewrite behavior
- the implementation does not require user Dockerfile changes for the supported matrix
