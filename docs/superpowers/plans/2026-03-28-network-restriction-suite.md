# Network Restriction Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a default-on hermetic integration suite that proves sandbox payloads cannot use direct outbound DNS, ICMP, raw TCP, raw UDP, or broadcast-style networking in either proxy or transparent mode.

**Architecture:** Keep the work entirely in the integration layer. Add strict helper plumbing for required host tools and transparent low-port prerequisites, then add one table-driven integration file that runs blocked-network probes against proxy and transparent sandboxes. Reuse existing local HTTP/HTTPS transparent fixtures only for transparent-mode preflight checks; everything else should stay hermetic via reserved test-network or namespace-local negative probes.

**Tech Stack:** Go, `go test`, bubblewrap network namespaces, host tools (`curl`, `ping`, `dig`/`nslookup`, `nc`), local HTTP/HTTPS fixtures

---

### File Structure

Planned file ownership and responsibilities:

- `integration/test_helpers_test.go`
  Strict host-tool resolution helpers, strict transparent low-port prerequisite checks, and shared network-suite helper utilities.
- `integration/network_restriction_test.go`
  Table-driven integration coverage for blocked DNS, ICMP, raw TCP, raw UDP, and broadcast-style probes in proxy and transparent modes.
- `integration/transparent_http_test.go`
  Adjust to use the strict transparent low-port prerequisite helper if helper naming/behavior changes.
- `integration/transparent_https_test.go`
  Adjust to use the strict transparent low-port prerequisite helper if helper naming/behavior changes.

### Task 1: Add strict integration helpers for host tools and transparent prerequisites

**Files:**
- Modify: `integration/test_helpers_test.go`

- [ ] **Step 1: Write the failing helper tests**

Add small testable pure helpers in `integration/test_helpers_test.go` or a nearby `_test.go` file and cover them with:

```go
func TestResolveFirstAvailableToolReturnsFirstInstalled(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "dig")
	second := filepath.Join(dir, "nslookup")
	if err := os.WriteFile(first, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := resolveFirstAvailableTool([]string{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if got != first {
		t.Fatalf("got %q want %q", got, first)
	}
}

func TestResolveFirstAvailableToolErrorsWhenMissing(t *testing.T) {
	_, err := resolveFirstAvailableTool([]string{"/definitely/missing-a", "/definitely/missing-b"})
	if err == nil {
		t.Fatal("expected missing tools to fail")
	}
	if !strings.Contains(err.Error(), "missing required tool") {
		t.Fatalf("unexpected error: %v", err)
	}
}
```

The helper should be pure so it can be tested without calling `t.Fatal`.

- [ ] **Step 2: Run the helper tests to verify they fail**

Run:

```bash
go test ./integration -run 'TestResolveFirstAvailableToolReturnsFirstInstalled|TestResolveFirstAvailableToolErrorsWhenMissing' -v
```

Expected: FAIL because `resolveFirstAvailableTool` does not exist yet.

- [ ] **Step 3: Write the minimal helper implementation**

Implement in `integration/test_helpers_test.go`:

```go
type networkToolPaths struct {
	curl string
	ping string
	dns  string
	nc   string
}

func resolveFirstAvailableTool(candidates []string) (string, error) {
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if strings.Contains(candidate, string(filepath.Separator)) {
			if _, err := os.Stat(candidate); err == nil {
				return candidate, nil
			}
			continue
		}
		if resolved, err := exec.LookPath(candidate); err == nil {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("missing required tool: %s", strings.Join(candidates, ", "))
}

func mustRequireNetworkTools(t *testing.T) networkToolPaths {
	t.Helper()

	curl, err := resolveFirstAvailableTool([]string{"curl"})
	if err != nil {
		t.Fatal(err)
	}
	ping, err := resolveFirstAvailableTool([]string{"ping"})
	if err != nil {
		t.Fatal(err)
	}
	dns, err := resolveFirstAvailableTool([]string{"dig", "nslookup"})
	if err != nil {
		t.Fatal(err)
	}
	nc, err := resolveFirstAvailableTool([]string{"nc"})
	if err != nil {
		t.Fatal(err)
	}

	return networkToolPaths{curl: curl, ping: ping, dns: dns, nc: nc}
}

func requireTransparentRuntimePortsStrict(t *testing.T) {
	t.Helper()

	for _, port := range []int{53, 80, 443} {
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatalf("transparent integration test requires binding %s: %v", addr, err)
		}
		_ = listener.Close()
	}
}
```

Also add a shared assertion helper:

```go
func assertBlockedRunResult(t *testing.T, result *bbox.RunResult, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("sandbox run transport failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected sandbox run result")
	}
	if result.ExitCode == 0 {
		t.Fatalf("expected blocked network command to fail, stdout=%q stderr=%q", string(result.Stdout), string(result.Stderr))
	}
}
```

If you rename `requireTransparentRuntimePorts`, update existing transparent integration tests to use the new strict helper name.

- [ ] **Step 4: Run the helper tests to verify they pass**

Run:

```bash
go test ./integration -run 'TestResolveFirstAvailableToolReturnsFirstInstalled|TestResolveFirstAvailableToolErrorsWhenMissing' -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add integration/test_helpers_test.go integration/transparent_http_test.go integration/transparent_https_test.go
git commit -m "test: add strict network integration helpers"
```

### Task 2: Add proxy-mode blocked network probe coverage

**Files:**
- Create: `integration/network_restriction_test.go`
- Modify: `integration/test_helpers_test.go`

- [ ] **Step 1: Write the failing proxy-mode integration test**

Add to `integration/network_restriction_test.go`:

```go
func TestNetworkRestrictionsProxyMode(t *testing.T) {
	requireSandboxPrereqs(t)
	tools := mustRequireNetworkTools(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	sandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "network-restrictions-proxy",
		Binaries: []string{tools.curl, tools.ping, tools.dns, tools.nc},
		Policy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^example[.]com$`},
			AllowHTTPMethods:  []string{"GET"},
		},
	})
	if err != nil {
		t.Fatalf("create proxy sandbox: %v", err)
	}
	defer sandbox.Close()

	probes := proxyBlockedProbeSpecs(tools)
	for _, probe := range probes {
		t.Run(probe.name, func(t *testing.T) {
			result, err := sandbox.Run(ctx, probe.argv, bbox.RunOptions{})
			assertBlockedRunResult(t, result, err)
		})
	}
}
```

Define the probe matrix so it covers:

- UDP DNS to a reserved TEST-NET resolver
- TCP DNS to a reserved TEST-NET resolver
- ICMP echo to a reserved TEST-NET address
- raw TCP connect to a reserved TEST-NET address
- raw UDP send to a reserved TEST-NET address
- broadcast-style ping or UDP send

Recommended concrete argv values:

```go
[]string{tools.dns, "@198.51.100.53", "example.test", "+time=1", "+tries=1"}
[]string{tools.dns, "+tcp", "@198.51.100.53", "example.test", "+time=1", "+tries=1"}
[]string{tools.ping, "-c", "1", "-W", "1", "198.51.100.1"}
[]string{tools.nc, "-zvw", "1", "198.51.100.1", "9"}
[]string{tools.nc, "-uzvw", "1", "198.51.100.1", "9"}
[]string{tools.ping, "-b", "-c", "1", "-W", "1", "255.255.255.255"}
```

If `nslookup` is selected instead of `dig`, branch the DNS argv generation accordingly in helper code.

- [ ] **Step 2: Run the proxy-mode test to verify it fails**

Run:

```bash
go test ./integration -run 'TestNetworkRestrictionsProxyMode' -v
```

Expected: FAIL because the new test file, probe helpers, or exact tool argv plumbing do not exist yet.

- [ ] **Step 3: Write the minimal proxy-mode implementation**

Implement in `integration/network_restriction_test.go`:

```go
type blockedProbeSpec struct {
	name string
	argv []string
}

func proxyBlockedProbeSpecs(tools networkToolPaths) []blockedProbeSpec {
	return []blockedProbeSpec{
		{name: "dns-udp", argv: dnsUDPProbeArgv(tools)},
		{name: "dns-tcp", argv: dnsTCPProbeArgv(tools)},
		{name: "icmp", argv: []string{tools.ping, "-c", "1", "-W", "1", "198.51.100.1"}},
		{name: "tcp", argv: []string{tools.nc, "-zvw", "1", "198.51.100.1", "9"}},
		{name: "udp", argv: []string{tools.nc, "-uzvw", "1", "198.51.100.1", "9"}},
		{name: "broadcast", argv: []string{tools.ping, "-b", "-c", "1", "-W", "1", "255.255.255.255"}},
	}
}
```

Keep the proxy test focused on non-zero exits only. Do not add brittle stderr matching unless one probe needs a minimal sanity check because the chosen tool can return zero spuriously.

- [ ] **Step 4: Run the proxy-mode test to verify it passes**

Run:

```bash
go test ./integration -run 'TestNetworkRestrictionsProxyMode' -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add integration/network_restriction_test.go integration/test_helpers_test.go
git commit -m "test: add proxy mode network restriction coverage"
```

### Task 3: Add transparent-mode blocked probe coverage plus transparent preflight

**Files:**
- Modify: `integration/network_restriction_test.go`
- Modify: `integration/test_helpers_test.go`
- Modify: `integration/transparent_http_test.go`
- Modify: `integration/transparent_https_test.go`

- [ ] **Step 1: Write the failing transparent-mode integration test**

Extend `integration/network_restriction_test.go` with:

```go
func TestNetworkRestrictionsTransparentMode(t *testing.T) {
	requireSandboxPrereqs(t)
	requireTransparentRuntimePortsStrict(t)
	tools := mustRequireNetworkTools(t)

	httpServer := startTransparentHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "allowed.localhost" {
			t.Fatalf("unexpected transparent HTTP host: %q", r.Host)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer httpServer.Close()

	httpsServer := startTransparentTLSTestServer(t, "secure.localhost", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "secure.localhost" {
			t.Fatalf("unexpected transparent HTTPS host: %q", r.Host)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer httpsServer.Close()
	trustHTTPSServer(t, httpsServer)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{
		MITM: bbox.MITMOptions{Enabled: true, MaxRequestBodyBytes: 1024},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	sandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:        "network-restrictions-transparent",
		Binaries:    []string{tools.curl, tools.ping, tools.dns, tools.nc},
		TrafficMode: bbox.TrafficModeTransparent,
		Policy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^allowed[.]localhost$`, `^secure[.]localhost$`},
			AllowHTTPMethods:  []string{"GET"},
			AllowPathPatterns: []string{`^/ok$`},
		},
	})
	if err != nil {
		t.Fatalf("create transparent sandbox: %v", err)
	}
	defer sandbox.Close()

	httpOK, err := sandbox.Run(ctx, []string{tools.curl, "-sS", "http://allowed.localhost/ok"}, bbox.RunOptions{})
	if err != nil || httpOK.ExitCode != 0 {
		t.Fatalf("transparent HTTP preflight failed: err=%v exit=%d stderr=%q", err, httpOK.ExitCode, string(httpOK.Stderr))
	}

	httpsOK, err := sandbox.Run(ctx, []string{tools.curl, "-sS", "https://secure.localhost/ok"}, bbox.RunOptions{})
	if err != nil || httpsOK.ExitCode != 0 {
		t.Fatalf("transparent HTTPS preflight failed: err=%v exit=%d stderr=%q", err, httpsOK.ExitCode, string(httpsOK.Stderr))
	}

	for _, probe := range transparentBlockedProbeSpecs(tools) {
		t.Run(probe.name, func(t *testing.T) {
			result, err := sandbox.Run(ctx, probe.argv, bbox.RunOptions{})
			assertBlockedRunResult(t, result, err)
		})
	}
}
```

The transparent blocked probe set should include the same DNS/ICMP/raw TCP/raw UDP/broadcast probes as proxy mode plus the already documented unsupported destination forms:

```go
[]string{tools.curl, "-sS", "--connect-timeout", "5", "--max-time", "10", "https://127.0.0.1/ok"}
[]string{tools.curl, "-sS", "--connect-timeout", "5", "--max-time", "10", "https://secure.localhost:8443/ok"}
```

- [ ] **Step 2: Run the transparent-mode test to verify it fails**

Run:

```bash
go test ./integration -run 'TestNetworkRestrictionsTransparentMode' -v
```

Expected: FAIL because the transparent matrix test and strict prerequisite plumbing do not exist yet.

- [ ] **Step 3: Write the minimal transparent-mode implementation**

Implement:

- `transparentBlockedProbeSpecs(tools networkToolPaths) []blockedProbeSpec`
- strict low-port helper usage in all transparent integration tests that rely on `:53`, `:80`, or `:443`

Recommended transparent probe matrix:

```go
func transparentBlockedProbeSpecs(tools networkToolPaths) []blockedProbeSpec {
	return []blockedProbeSpec{
		{name: "dns-udp-external", argv: dnsUDPProbeArgv(tools)},
		{name: "dns-tcp-external", argv: dnsTCPProbeArgv(tools)},
		{name: "icmp", argv: []string{tools.ping, "-c", "1", "-W", "1", "198.51.100.1"}},
		{name: "tcp", argv: []string{tools.nc, "-zvw", "1", "198.51.100.1", "9"}},
		{name: "udp", argv: []string{tools.nc, "-uzvw", "1", "198.51.100.1", "9"}},
		{name: "broadcast", argv: []string{tools.ping, "-b", "-c", "1", "-W", "1", "255.255.255.255"}},
		{name: "ip-literal-https", argv: []string{tools.curl, "-sS", "--connect-timeout", "5", "--max-time", "10", "https://127.0.0.1/ok"}},
		{name: "non-default-port-https", argv: []string{tools.curl, "-sS", "--connect-timeout", "5", "--max-time", "10", "https://secure.localhost:8443/ok"}},
	}
}
```

Do not duplicate the existing dedicated transparent integration assertions beyond a minimal preflight proving bbox-managed transparent HTTP/HTTPS still works before the blocked probes run.

- [ ] **Step 4: Run the transparent-mode test to verify it passes**

Run:

```bash
go test ./integration -run 'TestNetworkRestrictionsTransparentMode' -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add integration/network_restriction_test.go integration/test_helpers_test.go integration/transparent_http_test.go integration/transparent_https_test.go
git commit -m "test: add transparent mode network restriction coverage"
```

### Task 4: Run full verification and push

**Files:**
- Modify: none

- [ ] **Step 1: Run the focused network restriction suite**

Run:

```bash
go test ./integration -run 'TestNetworkRestrictionsProxyMode|TestNetworkRestrictionsTransparentMode' -v
```

Expected: PASS

- [ ] **Step 2: Run the full integration suite**

Run:

```bash
go test ./integration -v
```

Expected: PASS

- [ ] **Step 3: Run the full repository test suite**

Run:

```bash
go test ./...
```

Expected: PASS

- [ ] **Step 4: Inspect the tree**

Run:

```bash
git status --short
```

Expected: clean working tree

- [ ] **Step 5: Commit and push**

```bash
git push -u origin feature/network-restriction-suite
```

If no remote exists yet in the implementation environment, add the requested remote first:

```bash
git remote add origin git@github.com:moolen/bbox.git
git push -u origin feature/network-restriction-suite
```
