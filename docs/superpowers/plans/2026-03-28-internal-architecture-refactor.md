# Internal Sandbox Architecture Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the oversized sandbox internals into focused packages and files while preserving current proxy, transparent, MITM, tunnel, DNS, and exec behavior.

**Architecture:** Start with leaf concerns that already have clear behavior boundaries, then extract the helper-runtime transport and execution seams, then reduce `ProxyManager` and `helperClient` into coordinators over smaller collaborators. Use real subpackages for helper-runtime code, but keep manager-side and host-bridge collaborators inside `package bbox` as separate files and types because `compiledPolicy`, `Sandbox`, `RunResult`, and `accessEvent` are intentionally package-private today and forcing them across package boundaries would create a larger redesign than this phase allows.

**Tech Stack:** Go 1.25, standard library `net/http`/`net`/`context`, `golang.org/x/net/http2`, `golang.org/x/net/dns/dnsmessage`, `github.com/creack/pty`

---

## File Structure

### Helper Runtime

- Create: `internal/helperruntime/config.go`
- Create: `internal/helperruntime/proxy_mode.go`
- Create: `internal/helperruntime/transparent_mode.go`
- Create: `internal/helperruntime/bridge/bridge.go`
- Create: `internal/helperruntime/bridge/body.go`
- Create: `internal/helperruntime/dns/server.go`
- Create: `internal/helperruntime/dns/server_test.go`
- Create: `internal/helperruntime/ingress/proxy.go`
- Create: `internal/helperruntime/ingress/transparent.go`
- Create: `internal/helperruntime/ingress/connect.go`
- Create: `internal/helperruntime/ingress/mitm.go`
- Create: `internal/helperruntime/exec/session.go`
- Create: `internal/helperruntime/exec/session_test.go`
- Modify: `internal/helperruntime/runtime.go`
- Modify: `internal/helperruntime/runtime_test.go`

### Manager Side

- Create: `proxy_registry.go`
- Create: `proxy_registry_test.go`
- Create: `helper_binary.go`
- Create: `helper_binary_test.go`
- Create: `manager_connect_service.go`
- Create: `manager_proxy_service.go`
- Create: `manager_proxy_service_test.go`
- Create: `manager_audit.go`
- Modify: `manager.go`
- Modify: `manager_test.go`
- Modify: `api.go`
- Modify: `types.go`

### Host Bridge Client

- Create: `helper_client_bridge.go`
- Create: `helper_client_run.go`
- Create: `helper_client_tunnel.go`
- Create: `helper_client_tunnel_test.go`
- Modify: `helper_client.go`
- Modify: `helper_client_test.go`

### Integration / Docs

- Modify: `integration/transparent_http_test.go`
- Modify: `integration/transparent_https_test.go`
- Modify: `integration/connect_tunnel_test.go`
- Modify: `integration/mitm_https_test.go`
- Modify: `integration/mitm_h2_test.go`
- Modify: `README.md`

---

### Task 1: Lock In Current Runtime and Manager Seams

**Files:**
- Modify: `internal/helperruntime/runtime_test.go`
- Modify: `manager_test.go`
- Modify: `helper_client_test.go`

- [ ] **Step 1: Add focused characterization tests around the leaf seams that will move first**

```go
func TestReadBoundedResponseFlagsOversize(t *testing.T) {
	body := io.NopCloser(strings.NewReader("abcdef"))
	got, tooLarge, err := readBoundedResponse(body, 3)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abc" || !tooLarge {
		t.Fatalf("got %q tooLarge=%v", string(got), tooLarge)
	}
}

func TestValidateMITMHostAuthorityRejectsMismatch(t *testing.T) {
	if err := validateMITMHostAuthority("allowed.example", "127.0.0.1:443"); err == nil {
		t.Fatal("expected mismatch")
	}
}
```

- [ ] **Step 2: Add helper-client seam tests that do not depend on the monolithic type layout**

```go
func TestHelperClientTunnelActivationIsIdempotent(t *testing.T) {
	client := newHelperClient(nil, "sandbox-a", failingConn{writeErr: io.EOF})
	tunnel := &hostTunnel{}
	client.registerPendingTunnel(7, tunnel)
	if !client.activateTunnel(7) {
		t.Fatal("first activation should succeed")
	}
	if client.activateTunnel(7) {
		t.Fatal("second activation should fail")
	}
}
```

- [ ] **Step 3: Run the targeted tests to lock in the current behavior before extraction**

Run: `go test ./internal/helperruntime ./... -run 'Test(ReadBoundedResponseFlagsOversize|ValidateMITMHostAuthorityRejectsMismatch|HelperClientTunnelActivationIsIdempotent)'`

Expected: PASS and provide a characterization baseline before any code moves.

- [ ] **Step 4: Keep the tests package-local so later moves only require import updates, not assertion rewrites**

```go
// Keep assertions package-local for now; these tests become the safety net
// while functions move into smaller packages in later tasks.
```

- [ ] **Step 5: Re-run the targeted tests and make sure the safety-net tests pass**

Run: `go test ./internal/helperruntime ./... -run 'Test(ReadBoundedResponseFlagsOversize|ValidateMITMHostAuthorityRejectsMismatch|HelperClientTunnelActivationIsIdempotent)'`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/helperruntime/runtime_test.go manager_test.go helper_client_test.go
git commit -m "test: lock runtime manager and client seams"
```

### Task 2: Extract Helper Runtime Leaf Packages

**Files:**
- Create: `internal/helperruntime/dns/server.go`
- Create: `internal/helperruntime/dns/server_test.go`
- Create: `internal/helperruntime/bridge/body.go`
- Create: `internal/helperruntime/config.go`
- Create: `internal/helperruntime/proxy_mode.go`
- Create: `internal/helperruntime/transparent_mode.go`
- Modify: `internal/helperruntime/runtime.go`
- Modify: `internal/helperruntime/runtime_test.go`

- [ ] **Step 1: Write failing tests for the new DNS and body-limit leaf packages**

```go
func TestServerHandleQueryReturnsLoopbackARecord(t *testing.T) {
	payload := mustDNSQuery(t, dnsmessage.TypeA)
	response, ok := dns.HandleQuery(payload)
	if !ok || response == nil {
		t.Fatal("expected loopback DNS response")
	}
}

func TestReadBoundedBodyFlagsOversize(t *testing.T) {
	body := io.NopCloser(strings.NewReader("abcdef"))
	got, tooLarge, err := bridge.ReadBoundedBody(body, 3)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abc" || !tooLarge {
		t.Fatalf("got %q tooLarge=%v", string(got), tooLarge)
	}
}
```

- [ ] **Step 2: Run the new package tests to verify they fail because the packages do not exist yet**

Run: `go test ./internal/helperruntime/...`

Expected: FAIL with missing package or symbol errors for `dns.HandleQuery` and `bridge.ReadBoundedBody`.

- [ ] **Step 3: Implement the DNS and body helper packages and move runtime mode bootstrapping into focused files**

```go
// internal/helperruntime/dns/server.go
package dns

func HandleQuery(payload []byte) ([]byte, bool) { /* move existing logic verbatim */ }

// internal/helperruntime/bridge/body.go
package bridge

func ReadBoundedBody(body io.ReadCloser, maxBytes int64) ([]byte, bool, error) { /* move logic */ }
```

- [ ] **Step 4: Reduce `runtime.go` to the `Run` entrypoint and delegate proxy/transparent startup to the new files**

```go
func Run(ctx context.Context, cfg Config) error {
	cfg = withDefaults(cfg)
	switch cfg.TrafficMode {
	case TrafficModeProxy:
		return runProxyMode(ctx, cfg)
	case TrafficModeTransparent:
		return runTransparentMode(ctx, cfg)
	default:
		return fmt.Errorf("unsupported traffic mode %q", cfg.TrafficMode)
	}
}
```

- [ ] **Step 5: Run the helper-runtime test suite**

Run: `go test ./internal/helperruntime/...`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/helperruntime/config.go internal/helperruntime/proxy_mode.go internal/helperruntime/transparent_mode.go internal/helperruntime/bridge/body.go internal/helperruntime/dns/server.go internal/helperruntime/dns/server_test.go internal/helperruntime/runtime.go internal/helperruntime/runtime_test.go
git commit -m "refactor: extract helper runtime leaf packages"
```

### Task 3: Extract Helper Runtime Bridge Coordination

**Files:**
- Create: `internal/helperruntime/bridge/bridge.go`
- Modify: `internal/helperruntime/runtime.go`
- Modify: `internal/helperruntime/runtime_test.go`
- Modify: `integration/connect_tunnel_test.go`

- [ ] **Step 1: Add failing tests for bridge request correlation and tunnel delivery**

```go
func TestBridgeDeliversTunnelFramesToRegisteredChannel(t *testing.T) {
	b := newTestBridgeRuntime(t)
	ch := b.RegisterTunnel(42)
	b.DeliverTunnel(helperproto.Envelope{ID: 42, TunnelFrame: &helperproto.TunnelFrame{Data: []byte("ping")}})
	select {
	case env := <-ch:
		if string(env.TunnelFrame.Data) != "ping" {
			t.Fatalf("got %q", string(env.TunnelFrame.Data))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for tunnel frame")
	}
}
```

- [ ] **Step 2: Run bridge-focused tests and verify the new package API is still missing**

Run: `go test ./internal/helperruntime/... -run 'TestBridge'`

Expected: FAIL with missing `bridge` package API or constructor errors.

- [ ] **Step 3: Move the bridge type, send loop, request correlation, and tunnel bookkeeping into `internal/helperruntime/bridge`**

```go
type RuntimeBridge struct {
	// existing bridge state moved here with narrow exported methods
}

func New(conn io.ReadWriteCloser, logger *log.Logger, proxyAddr string) *RuntimeBridge
func (b *RuntimeBridge) ReadLoop(ctx context.Context) error
func (b *RuntimeBridge) DeliverTunnel(env helperproto.Envelope)
func (b *RuntimeBridge) RegisterTunnel(id uint64) chan helperproto.Envelope
```

- [ ] **Step 4: Update runtime boot files and the existing root-package handlers to depend on the bridge package primitives instead of private cross-file globals**

```go
bridge := bridgepkg.New(cfg.Bridge, cfg.Logger, listener.Addr().String())
server := &http.Server{Handler: proxyHandler(bridge)}
```

Use `DeliverTunnel` as the explicit test and runtime hook for tunnel-frame injection. Handler construction stays in the root package for this task; Task 4 moves HTTP handler construction and transparent HTTPS serving into `internal/helperruntime/ingress` once the bridge primitives are already extracted.

- [ ] **Step 5: Run helper-runtime and tunnel integration tests**

Run: `go test ./internal/helperruntime/... ./integration -run 'Test(Bridge|ConnectTunnel)'`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/helperruntime/bridge/bridge.go internal/helperruntime/runtime.go internal/helperruntime/runtime_test.go integration/connect_tunnel_test.go
git commit -m "refactor: extract helper runtime bridge coordination"
```

### Task 4: Extract Helper Runtime Ingress and Exec Packages

**Files:**
- Create: `internal/helperruntime/ingress/proxy.go`
- Create: `internal/helperruntime/ingress/transparent.go`
- Create: `internal/helperruntime/ingress/connect.go`
- Create: `internal/helperruntime/ingress/mitm.go`
- Create: `internal/helperruntime/exec/session.go`
- Create: `internal/helperruntime/exec/session_test.go`
- Modify: `internal/helperruntime/runtime.go`
- Modify: `internal/helperruntime/runtime_test.go`
- Modify: `integration/transparent_http_test.go`
- Modify: `integration/transparent_https_test.go`
- Modify: `integration/mitm_https_test.go`
- Modify: `integration/mitm_h2_test.go`

- [ ] **Step 1: Add failing tests for ingress request rewriting and exec session lifecycle**

```go
func TestRewriteTransparentHTTPRequestBuildsAbsoluteURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/path?q=1", nil)
	req.Host = "example.com"
	rewritten, err := ingress.RewriteTransparentHTTPRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if rewritten.URL.String() != "http://example.com/path?q=1" {
		t.Fatalf("got %q", rewritten.URL.String())
	}
}

func TestStartExecSessionInteractiveUsesPTY(t *testing.T) {
	_, streams, err := hrexec.StartSession(exec.Command("sh"), helperproto.ExecRequest{Interactive: true, Terminal: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(streams) == 0 {
		t.Fatal("expected output streams")
	}
}
```

- [ ] **Step 2: Run the targeted tests to verify package APIs are not present yet**

Run: `go test ./internal/helperruntime/... -run 'Test(RewriteTransparentHTTPRequest|StartExecSessionInteractiveUsesPTY)'`

Expected: FAIL with missing `ingress` or `exec` package symbols.

- [ ] **Step 3: Move HTTP rewrite helpers, CONNECT/MITM handlers, and transparent HTTPS serving into `internal/helperruntime/ingress`**

```go
type Bridge interface {
	RegisterTunnel(id uint64) chan helperproto.Envelope
	DeliverTunnel(env helperproto.Envelope)
	ReadLoop(ctx context.Context) error
}

func ProxyHandler(rt Bridge) http.Handler
func TransparentHTTPHandler(rt Bridge) http.Handler
func ServeTransparentHTTPSConn(conn net.Conn, rt Bridge)
```

- [ ] **Step 4: Move exec session creation, output streaming, and input handling into `internal/helperruntime/exec`**

```go
type Session struct { /* moved exec session state */ }

func StartSession(cmd *exec.Cmd, req helperproto.ExecRequest) (*Session, []OutputStream, error)
func HandleInput(session *Session, input helperproto.ExecInput)
```

- [ ] **Step 5: Reconnect the root runtime bootstrapping to the new ingress and exec packages and keep the public `helperruntime.Run` entrypoint stable**

Run: `go test ./internal/helperruntime/... ./integration -run 'Test(Transparent|MITM)'`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/helperruntime/ingress/proxy.go internal/helperruntime/ingress/transparent.go internal/helperruntime/ingress/connect.go internal/helperruntime/ingress/mitm.go internal/helperruntime/exec/session.go internal/helperruntime/exec/session_test.go internal/helperruntime/runtime.go internal/helperruntime/runtime_test.go integration/transparent_http_test.go integration/transparent_https_test.go integration/mitm_https_test.go integration/mitm_h2_test.go
git commit -m "refactor: extract helper runtime ingress and exec"
```

### Task 5: Extract Manager Registry and Helper Binary Resolution

**Files:**
- Create: `proxy_registry.go`
- Create: `proxy_registry_test.go`
- Create: `helper_binary.go`
- Create: `helper_binary_test.go`
- Modify: `manager.go`
- Modify: `manager_test.go`

- [ ] **Step 1: Write failing tests for sandbox registration and helper binary resolution as isolated collaborators**

```go
func TestRegistryRejectsDuplicateSandboxID(t *testing.T) {
	r := newSandboxRegistry(nil)
	if err := r.Register("sandbox-a", nil); err != nil {
		t.Fatal(err)
	}
	if err := r.Register("sandbox-a", nil); err == nil {
		t.Fatal("expected duplicate registration to fail")
	}
}

func TestPackageRootFindsModuleRoot(t *testing.T) {
	root, err := packageRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 2: Run the targeted tests and verify the new packages do not exist yet**

Run: `go test ./... -run 'Test(RegistryRejectsDuplicateSandboxID|PackageRootFindsModuleRoot)'`

Expected: FAIL with unresolved `newSandboxRegistry` or relocated helper-binary helpers.

- [ ] **Step 3: Implement the new registry and helper-binary collaborators in focused `package bbox` files and replace direct map/build logic inside `ProxyManager`**

```go
type sandboxRegistry struct { /* moved sandbox maps and mutex */ }

func newSandboxRegistry(defaultPolicy *compiledPolicy) *sandboxRegistry
func (r *sandboxRegistry) Register(id string, policy *compiledPolicy) error
func (r *sandboxRegistry) Attach(id string, sandbox *Sandbox) error

type helperBinaryResolver struct { /* moved once/build-dir state */ }

func (r *helperBinaryResolver) HelperBinary() (string, error)
```

- [ ] **Step 4: Reduce `ProxyManager` to dependency wiring and delegating wrappers**

```go
type ProxyManager struct {
	registry *sandboxRegistry
	resolver *helperBinaryResolver
}
```

- [ ] **Step 5: Run manager-focused tests**

Run: `go test ./... -run 'TestProxyManagerRegistryLifecycle|TestPackageRootFindsModuleRoot'`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add proxy_registry.go proxy_registry_test.go helper_binary.go helper_binary_test.go manager.go manager_test.go
git commit -m "refactor: extract manager registry and helper resolution"
```

### Task 6: Extract Manager Proxy, Connect, and Audit Services

**Files:**
- Create: `manager_connect_service.go`
- Create: `manager_proxy_service.go`
- Create: `manager_proxy_service_test.go`
- Create: `manager_audit.go`
- Modify: `manager.go`
- Modify: `manager_test.go`
- Modify: `api.go`
- Modify: `types.go`
- Modify: `README.md`

- [ ] **Step 1: Write failing tests for the extracted proxy/connect services around policy evaluation and body-limit configuration**

```go
func TestProxyServiceRejectsOversizedMITMBody(t *testing.T) {
	svc := newManagerProxyService(managerProxyConfig{maxRequestBodyBytes: 3})
	resp := svc.HandleMITMRequest(context.Background(), testPolicy(), "sandbox-a", helperproto.MITMRequest{
		Scheme: "https",
		Host:   "example.com",
		Method: http.MethodPost,
		Path:   "/upload",
		Body:   []byte("abcdef"),
	})
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d", resp.StatusCode)
	}
}
```

- [ ] **Step 2: Run the targeted tests and verify the extracted service APIs are not present yet**

Run: `go test ./... -run 'TestProxyServiceRejectsOversizedMITMBody'`

Expected: FAIL with unresolved `newManagerProxyService` or config symbols.

- [ ] **Step 3: Move proxy request handling, MITM handling, authority validation, response buffering, CONNECT authorization, and audit fanout into focused service types**

```go
type managerProxyService struct {
	transport *http.Transport
	record    func(accessEvent)
}

func (s *managerProxyService) HandleProxyRequest(ctx context.Context, sandboxID string, req helperproto.ProxyRequest) *helperproto.ProxyResponse
func (s *managerProxyService) HandleMITMRequest(ctx context.Context, sandboxID string, req helperproto.MITMRequest) *helperproto.MITMResponse
```

- [ ] **Step 4: Apply the small API cleanup for body-size limits in `ProxyOptions`/`MITMOptions` and update README examples**

```go
type ProxyOptions struct {
	MaxRequestBodyBytes  int64
	MaxResponseBodyBytes int64
	MITM                 MITMOptions
}
```

- [ ] **Step 5: Run manager and MITM test coverage**

Run: `go test ./... -run 'TestProxyManager|TestHandleProxyRequest|TestProxyService|Test.*MITM'`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add manager_connect_service.go manager_proxy_service.go manager_proxy_service_test.go manager_audit.go manager.go manager_test.go api.go types.go README.md
git commit -m "refactor: extract manager traffic services"
```

### Task 7: Extract Host Bridge Client Run and Tunnel Collaborators

**Files:**
- Create: `helper_client_bridge.go`
- Create: `helper_client_run.go`
- Create: `helper_client_tunnel.go`
- Create: `helper_client_tunnel_test.go`
- Modify: `helper_client.go`
- Modify: `helper_client_test.go`

- [ ] **Step 1: Write failing tests for the new run-session and tunnel collaborators**

```go
func TestRunSessionFinishIsSingleShot(t *testing.T) {
	session := newRunSession(io.Discard, io.Discard)
	if !session.Finish(&RunResult{ExitCode: 0}, nil) {
		t.Fatal("first finish should win")
	}
	if session.Finish(&RunResult{ExitCode: 1}, errors.New("late")) {
		t.Fatal("second finish should be ignored")
	}
}

func TestTunnelWriteCloseSendsTerminalCloseOnce(t *testing.T) {
	client := newHelperClient(nil, "sandbox-a", &recordingConn{})
	tunnel := newHostTunnel(client, 7, nopConn{})
	tunnel.SendWriteClose(io.EOF)
	tunnel.SendWriteClose(io.EOF)
	if got := countTunnelCloseEnvelopes(client.conn.(*recordingConn).frames, 7); got != 1 {
		t.Fatalf("expected 1 tunnel close envelope, got %d", got)
	}
}
```

- [ ] **Step 2: Run the targeted tests and verify the new collaborators are not implemented yet**

Run: `go test ./... -run 'Test(RunSessionFinishIsSingleShot|TunnelWriteCloseSendsTerminalCloseOnce)'`

Expected: FAIL with unresolved `newRunSession` or split tunnel helpers.

- [ ] **Step 3: Move run-state completion logic and stdin/resize pumps into focused helper-client files**

```go
type runSession struct {
	resultCh chan runOutcome
}

func newRunSession(stdout, stderr io.Writer) *runSession
func (s *runSession) Finish(result *RunResult, err error) bool
```

- [ ] **Step 4: Move host tunnel lifecycle and relay logic into `helper_client_tunnel.go`, then reduce `helperClient` to bridge/process orchestration**

```go
type helperClient struct {
	runSession *runSession
	tunnels    map[uint64]*hostTunnel
}
```

- [ ] **Step 5: Run helper-client tests**

Run: `go test ./... -run 'TestHelperClient'`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add helper_client_bridge.go helper_client_run.go helper_client_tunnel.go helper_client_tunnel_test.go helper_client.go helper_client_test.go
git commit -m "refactor: extract host bridge client collaborators"
```

### Task 8: Final Integration Verification and Cleanup

**Files:**
- Modify: `manager.go`
- Modify: `helper_client.go`
- Modify: `internal/helperruntime/runtime.go`
- Modify: `README.md`

- [ ] **Step 1: Remove any dead compatibility shims left behind by the extractions**

```go
// Delete moved helper functions from the old monolithic files once all call sites
// use the new packages and tests cover the new seams.
```

- [ ] **Step 2: Run formatting across the touched Go files**

Run: `gofmt -w manager.go helper_client.go proxy_registry.go helper_binary.go manager_connect_service.go manager_proxy_service.go manager_audit.go helper_client_bridge.go helper_client_run.go helper_client_tunnel.go internal/helperruntime/*.go internal/helperruntime/bridge/*.go internal/helperruntime/dns/*.go internal/helperruntime/ingress/*.go internal/helperruntime/exec/*.go`

Expected: files are reformatted with no errors.

- [ ] **Step 3: Run the full test suite**

Run: `go test ./...`

Expected: PASS

- [ ] **Step 4: Inspect the remaining file sizes to confirm the architectural goal was actually met**

Run: `wc -l internal/helperruntime/runtime.go manager.go helper_client.go`

Expected: each file is materially smaller than the current baselines of `1632`, `865`, and `792` lines.

- [ ] **Step 5: Review exported API diffs for accidental breakage beyond the approved small cleanups**

Run: `git diff --stat HEAD~8..HEAD`

Expected: new packages and smaller core files; no unrelated feature changes.

- [ ] **Step 6: Verify dependency direction still matches the design rules**

Run: `go list -f '{{.ImportPath}} {{join .Imports " "}}' ./... | rg 'internal/helperruntime/(bridge|dns|exec|ingress)|github.com/moolen/bbox$'`

Expected: `internal/helperruntime/bridge` does not import `ingress` or `exec`; `internal/helperruntime/exec` does not import `ingress` or `dns`; manager registry/helper-binary files remain free of proxy-logic dependencies.

- [ ] **Step 7: Commit**

```bash
git add README.md manager.go helper_client.go internal/helperruntime/runtime.go
git commit -m "refactor: finish internal architecture cleanup"
```
