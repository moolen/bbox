# Phase 2 CONNECT Tunnels Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add hardened HTTP `CONNECT` tunneling to `github.com/moolen/bbox` so sandboxed payloads can open proxied TCP tunnels subject to per-sandbox host and port policy.

**Architecture:** Keep the current helper bridge model. Normal HTTP proxying continues to use request/response messages, while `CONNECT` adds explicit connect and tunnel messages so the helper can relay bytes between the sandbox-side proxy socket and a host-opened outbound TCP connection without giving the sandbox direct network capability.

**Tech Stack:** Go, `net`, `net/http`, `encoding/gob`, `bubblewrap`, `curl`, existing helper bridge protocol

---

## File Structure

The Phase 2 `CONNECT` slice should converge on these responsibilities:

- `types.go`
  Extend `NetworkPolicy` with `AllowConnectPorts`
- `policy.go`
  Parse exact ports and ranges, validate `CONNECT` targets, and enforce host + port policy
- `policy_test.go`
  Unit coverage for connect-port parsing and policy checks
- `internal/helperproto/messages.go`
  Add explicit connect/tunnel bridge messages
- `internal/helperproto/messages_test.go`
  Gob round-trip coverage for connect/tunnel messages
- `internal/helperruntime/runtime.go`
  Handle proxy `CONNECT`, hijack the sandbox-side proxy connection, and shuttle tunnel frames
- `internal/helperruntime/runtime_test.go`
  Bridge/runtime tests for connect handshake and tunnel lifecycle
- `helper_client.go`
  Dispatch host-side connect requests and tunnel frames from the helper bridge
- `helper_client_test.go`
  Unit coverage for host-side bridge tunnel handling
- `manager.go`
  Enforce policy for `CONNECT`, open outbound TCP connections, and relay tunnel bytes
- `integration/connect_tunnel_test.go`
  End-to-end test for allowed and denied tunnel behavior using one shared proxy manager and multiple sandboxes
- `cmd/demo/main.go`
  Optional `CONNECT` demo path once the library flow passes
- `README.md`
  Document the `AllowConnectPorts` policy and demo behavior if the CLI changes

### Task 1: Extend the policy model for allowed CONNECT ports

**Files:**
- Modify: `types.go`
- Modify: `policy.go`
- Modify: `policy_test.go`

- [ ] **Step 1: Write the failing tests**

Add unit coverage for exact ports, ranges, and default-deny behavior:

```go
func TestCompilePolicyParsesAllowedConnectPorts(t *testing.T) {
	policy, err := compilePolicy(NetworkPolicy{
		AllowConnect:      true,
		AllowConnectPorts: []string{"443", "8443", "10000-10100"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Check(http.MethodConnect, "example.com:443", true); err != nil {
		t.Fatalf("expected 443 to be allowed: %v", err)
	}
	if err := policy.Check(http.MethodConnect, "example.com:10050", true); err != nil {
		t.Fatalf("expected range port to be allowed: %v", err)
	}
}

func TestCompilePolicyRejectsInvalidConnectPortSpec(t *testing.T) {
	_, err := compilePolicy(NetworkPolicy{
		AllowConnect:      true,
		AllowConnectPorts: []string{"443-22"},
	})
	if err == nil {
		t.Fatal("expected invalid descending range to fail")
	}
}

func TestCompiledPolicyDeniesConnectWithoutAllowedPortMatch(t *testing.T) {
	policy, err := compilePolicy(NetworkPolicy{
		AllowHostPatterns: []string{`^example[.]com$`},
		AllowConnect:      true,
		AllowConnectPorts: []string{"443"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Check(http.MethodConnect, "example.com:8443", true); err == nil {
		t.Fatal("expected CONNECT to unmatched port to be denied")
	}
}
```

- [ ] **Step 2: Run the policy tests to verify they fail**

Run: `go test ./... -run 'TestCompilePolicyParsesAllowedConnectPorts|TestCompilePolicyRejectsInvalidConnectPortSpec|TestCompiledPolicyDeniesConnectWithoutAllowedPortMatch'`
Expected: FAIL because `AllowConnectPorts` and range parsing do not exist yet

- [ ] **Step 3: Write the minimal implementation**

Extend the public policy type:

```go
type NetworkPolicy struct {
	AllowHostPatterns []string
	DenyHostPatterns  []string
	AllowHTTPMethods  []string
	AllowConnect      bool
	AllowConnectPorts []string
}
```

Add parsed connect-port rules in `policy.go`:

```go
type portRange struct {
	start int
	end   int
}

type compiledPolicy struct {
	allowMethods  map[string]struct{}
	allowHosts    []*regexp.Regexp
	denyHosts     []*regexp.Regexp
	allowConnect  bool
	connectPorts  []portRange
}
```

Implement helpers:

- `parseConnectPortSpec(string) (portRange, error)`
- `matchConnectPort([]portRange, int) bool`
- `splitConnectTarget(hostport string) (host string, port int, err error)`

Update `Check` so `CONNECT`:

- requires a valid `host:port`
- requires `AllowConnect=true`
- requires at least one configured port range and a matching port
- still applies hostname deny/allow regexes

- [ ] **Step 4: Run the policy tests to verify they pass**

Run: `go test ./... -run 'TestCompilePolicyParsesAllowedConnectPorts|TestCompilePolicyRejectsInvalidConnectPortSpec|TestCompiledPolicyDeniesConnectWithoutAllowedPortMatch'`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add types.go policy.go policy_test.go
git commit -m "feat: add connect port policy rules"
```

### Task 2: Add explicit CONNECT and tunnel messages to the helper protocol

**Files:**
- Modify: `internal/helperproto/messages.go`
- Modify: `internal/helperproto/messages_test.go`

- [ ] **Step 1: Write the failing protocol tests**

Add round-trip coverage for the new message types:

```go
func TestConnectRequestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)

	want := Envelope{
		ID: 9,
		ConnectRequest: &ConnectRequest{
			Host: "example.com",
			Port: 443,
		},
	}
	if err := enc.Encode(&want); err != nil {
		t.Fatal(err)
	}

	var got Envelope
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ConnectRequest == nil || got.ConnectRequest.Port != 443 {
		t.Fatalf("unexpected connect request: %#v", got.ConnectRequest)
	}
}
```

- [ ] **Step 2: Run the protocol tests to verify they fail**

Run: `go test ./internal/helperproto -run TestConnectRequestRoundTrip`
Expected: FAIL with undefined `ConnectRequest`

- [ ] **Step 3: Write the minimal implementation**

Add new envelope fields:

```go
type Envelope struct {
	ID              uint64
	Hello           *Hello
	Ready           *Ready
	ProxyRequest    *ProxyRequest
	ProxyResponse   *ProxyResponse
	ConnectRequest  *ConnectRequest
	ConnectResponse *ConnectResponse
	TunnelFrame     *TunnelFrame
	TunnelClose     *TunnelClose
	ExecRequest     *ExecRequest
	StreamFrame     *StreamFrame
	ExecResult      *ExecResult
}
```

Add message types:

```go
type ConnectRequest struct {
	Host string
	Port int
}

type ConnectResponse struct {
	StatusCode int
	Message    string
	Error      string
}

type TunnelFrame struct {
	Data []byte
}

type TunnelClose struct {
	Write bool
	Error string
}
```

Update `Envelope.Kind()` accordingly.

- [ ] **Step 4: Run the protocol tests to verify they pass**

Run: `go test ./internal/helperproto -run TestConnectRequestRoundTrip`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/helperproto/messages.go internal/helperproto/messages_test.go
git commit -m "feat: add connect tunnel bridge messages"
```

### Task 3: Implement CONNECT handling in the helper runtime

**Files:**
- Modify: `internal/helperruntime/runtime.go`
- Modify: `internal/helperruntime/runtime_test.go`

- [ ] **Step 1: Write the failing runtime tests**

Add focused tests around the helper-side handshake and proxy behavior:

```go
func TestProxyHandlerRejectsMalformedConnectTarget(t *testing.T) {
	bridge, peer, errCh := startReadLoop(t, "127.0.0.1:31111")
	defer bridge.Close()
	defer peer.Close()

	req := httptest.NewRequest(http.MethodConnect, "http://invalid target", nil)
	w := httptest.NewRecorder()

	newBridge(bridge, log.New(io.Discard, "", 0), "127.0.0.1:31111").proxyHandler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request, got %d", w.Code)
	}

	closeReadLoop(t, peer, errCh)
}
```

Add one bridge-level test that proves a `ConnectRequest` is emitted and a denial response is returned to the client.

- [ ] **Step 2: Run the helper runtime tests to verify they fail**

Run: `go test ./internal/helperruntime -run 'TestProxyHandlerRejectsMalformedConnectTarget|TestProxyHandlerConnectDenied'`
Expected: FAIL because `CONNECT` is currently rejected as not implemented

- [ ] **Step 3: Write the minimal implementation**

Update `proxyHandler()` to branch on `CONNECT`:

- validate `req.Host`
- hijack the proxy connection using `http.Hijacker`
- call a new helper bridge method like:

```go
func (b *bridge) connect(ctx context.Context, host string, port int) (*helperproto.ConnectResponse, error)
```

- on denial, write an HTTP proxy error response and close
- on success, write `HTTP/1.1 200 Connection Established\r\n\r\n`
- start two relay loops:
  - payload socket -> `TunnelFrame`
  - bridge `TunnelFrame` -> payload socket

Use a separate pending-response map or shared request correlation for connect handshakes. Keep tunnel frames isolated from exec `StreamFrame`.

- [ ] **Step 4: Run the helper runtime tests to verify they pass**

Run: `go test ./internal/helperruntime -run 'TestProxyHandlerRejectsMalformedConnectTarget|TestProxyHandlerConnectDenied'`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/helperruntime/runtime.go internal/helperruntime/runtime_test.go
git commit -m "feat: add helper runtime connect handling"
```

### Task 4: Implement host-side tunnel dialing and relay in the manager bridge

**Files:**
- Modify: `helper_client.go`
- Modify: `helper_client_test.go`
- Modify: `manager.go`

- [ ] **Step 1: Write the failing host-side tests**

Add a unit test proving the helper client forwards a `ConnectRequest` to the manager and emits the response:

```go
func TestHelperClientHandlesConnectRequest(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{
		AllowHostPatterns: []string{`^example[.]com$`},
		AllowConnect:      true,
		AllowConnectPorts: []string{"443"},
	}))
	client := newHelperClient(manager, "sandbox-a", clientSide)

	go func() {
		client.loopDone <- client.readLoop()
	}()

	enc := gob.NewEncoder(serverSide)
	dec := gob.NewDecoder(serverSide)
	if err := enc.Encode(&helperproto.Envelope{
		ID: 3,
		ConnectRequest: &helperproto.ConnectRequest{
			Host: "example.com",
			Port: 443,
		},
	}); err != nil {
		t.Fatal(err)
	}

	var got helperproto.Envelope
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ConnectResponse == nil || got.ConnectResponse.StatusCode != http.StatusOK {
		t.Fatalf("unexpected connect response: %#v", got.ConnectResponse)
	}
}
```

- [ ] **Step 2: Run the host-side tests to verify they fail**

Run: `go test ./... -run TestHelperClientHandlesConnectRequest`
Expected: FAIL because the helper client does not understand connect messages yet

- [ ] **Step 3: Write the minimal implementation**

Extend `helperClient.readLoop()` to handle:

- `ConnectRequest`
- `TunnelFrame`
- `TunnelClose`

Add host-side manager helpers:

```go
func (m *ProxyManager) handleConnectRequest(ctx context.Context, sandboxID string, req helperproto.ConnectRequest) *helperproto.ConnectResponse
func (m *ProxyManager) dialTunnel(ctx context.Context, host string, port int) (net.Conn, error)
```

Host behavior:

- enforce per-sandbox policy with hostname and port
- return `403` on policy denial
- open outbound TCP connection with a fixed dial timeout
- start bidirectional copy loops between the outbound socket and bridge tunnel frames
- send close notifications exactly once when each side finishes

Hardening requirements:

- no tunnel without a successful connect handshake
- no leaked goroutines on early close
- map dial failures to `502`
- use a bounded idle deadline or periodic deadline refresh on the outbound socket

- [ ] **Step 4: Run the host-side tests to verify they pass**

Run: `go test ./... -run TestHelperClientHandlesConnectRequest`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add helper_client.go helper_client_test.go manager.go
git commit -m "feat: add host connect tunnel relay"
```

### Task 5: Add end-to-end CONNECT integration coverage

**Files:**
- Create: `integration/connect_tunnel_test.go`

- [ ] **Step 1: Write the failing integration test**

Add a self-contained integration test that proves one sandbox may tunnel and another may not:

```go
func TestTwoSandboxesUseDifferentConnectPolicies(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetLn.Close()

	go serveMinimalHTTPOverTCP(t, targetLn)

	port := targetLn.Addr().(*net.TCPAddr).Port
	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	allowed, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "allowed",
		Binaries: []string{"curl"},
		Policy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^127[.]0[.]0[.]1$`},
			AllowConnect:      true,
			AllowConnectPorts: []string{strconv.Itoa(port)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer allowed.Close()

	denied, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "denied",
		Binaries: []string{"curl"},
		Policy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^127[.]0[.]0[.]1$`},
			AllowConnect:      true,
			AllowConnectPorts: []string{"443"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()

	targetURL := fmt.Sprintf("http://127.0.0.1:%d/ok", port)
	okRes, err := allowed.Run(ctx, []string{"curl", "--proxytunnel", "-x", "http://127.0.0.1:31111", "-sS", targetURL}, bbox.RunOptions{})
	if err != nil || okRes.ExitCode != 0 {
		t.Fatalf("expected allowed tunnel to succeed, got result=%+v err=%v", okRes, err)
	}

	badRes, err := denied.Run(ctx, []string{"curl", "--proxytunnel", "-x", "http://127.0.0.1:31111", "-sS", targetURL}, bbox.RunOptions{})
	if err == nil && badRes.ExitCode == 0 {
		t.Fatalf("expected denied tunnel to fail, got result=%+v err=%v", badRes, err)
	}
}
```

- [ ] **Step 2: Run the integration test to verify it fails**

Run: `go test ./integration -run TestTwoSandboxesUseDifferentConnectPolicies -v`
Expected: FAIL because `CONNECT` tunneling is not implemented end-to-end yet

- [ ] **Step 3: Write the minimal implementation adjustments**

Fix any gaps exposed by the integration test, especially:

- helper handshake ordering
- tunnel close propagation
- `curl --proxytunnel` compatibility with the helper’s proxy response formatting
- per-sandbox port allowlist enforcement

- [ ] **Step 4: Run the integration test to verify it passes**

Run: `go test ./integration -run TestTwoSandboxesUseDifferentConnectPolicies -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add integration/connect_tunnel_test.go
git commit -m "test: cover connect tunnels across sandboxes"
```

### Task 6: Update the demo and documentation if the tunnel path is stable

**Files:**
- Modify: `cmd/demo/main.go`
- Modify: `README.md`

- [ ] **Step 1: Write the failing smoke expectation**

Document the desired demo shape:

```text
go run ./cmd/demo --connect-demo

Expected:
- the default HTTP allow/deny example still works
- an optional CONNECT example shows one allowed tunnel and one denied tunnel
```

- [ ] **Step 2: Run the demo to verify the connect path is not ready yet**

Run: `go run ./cmd/demo --connect-demo`
Expected: FAIL because the CLI does not expose a connect demo yet

- [ ] **Step 3: Write the minimal implementation**

Add an optional connect example behind a flag:

- preserve the existing default HTTP demo behavior
- add a small local target server for the connect example
- print concise success/denial output

Update the README with:

- `AllowConnectPorts` examples
- explicit note that `CONNECT` is tunneled, not MITM’d

- [ ] **Step 4: Run final verification**

Run: `go test ./...`
Expected: PASS

Run: `go test ./integration -run TestTwoSandboxesUseDifferentConnectPolicies -v`
Expected: PASS

Run: `go run ./cmd/demo`
Expected: existing HTTP demo still succeeds

Run: `go run ./cmd/demo --connect-demo`
Expected: optional connect demo shows one allowed tunnel and one denied tunnel

- [ ] **Step 5: Commit**

```bash
git add cmd/demo/main.go README.md
git commit -m "feat: document and demo connect tunnels"
```
