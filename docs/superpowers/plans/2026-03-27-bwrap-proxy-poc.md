# Bwrap Proxy PoC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Go proof of concept that launches `curl -v http://example.com` inside a `bwrap` sandbox with its own network namespace and filesystem view, while routing HTTP traffic through a proxy listener reachable as `http://localhost:31111` from inside the sandbox.

**Architecture:** The parent Go process stages a minimal sandbox root with `curl` and its runtime dependencies, spawns `bwrap` with a gated child command, temporarily joins the child network namespace on a locked thread to bind `127.0.0.1:31111`, then switches back to the host network namespace and serves proxy requests through that inherited listener. The child process sees only the copied filesystem subset and the loopback proxy endpoint inside its own net namespace.

**Tech Stack:** Go, `bubblewrap`, Linux user/net namespaces, Go `net/http`, `golang.org/x/sys/unix`

---

### Task 1: Bootstrap module and test harness

**Files:**
- Create: `go.mod`
- Create: `main_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestParseLddOutput(t *testing.T) {
	input := "\tlibcurl.so.4 => /usr/lib/libcurl.so.4 (0x0)\n\t/lib64/ld-linux-x86-64.so.2 (0x0)\n"
	got := parseLddOutput(input)
	want := []string{"/usr/lib/libcurl.so.4", "/lib64/ld-linux-x86-64.so.2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./...`
Expected: FAIL with undefined `parseLddOutput`

- [ ] **Step 3: Write minimal implementation**

Create the module and add a small implementation stub in `sandbox.go` later so the parser can exist.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./...`
Expected: PASS for `TestParseLddOutput`

- [ ] **Step 5: Commit**

```bash
git add go.mod main_test.go sandbox.go
git commit -m "test: add sandbox dependency parser coverage"
```

### Task 2: Build sandbox root and `bwrap` command

**Files:**
- Create: `sandbox.go`
- Modify: `main_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestBuildBwrapArgsSetsProxyAndNamespaceFlags(t *testing.T) {
	args := buildBwrapArgs("/tmp/root", 7)
	joined := strings.Join(args, " ")
	for _, needle := range []string{"--unshare-user", "--unshare-net", "HTTP_PROXY", "localhost:31111"} {
		if !strings.Contains(joined, needle) {
			t.Fatalf("missing %q in %q", needle, joined)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./...`
Expected: FAIL with undefined `buildBwrapArgs`

- [ ] **Step 3: Write minimal implementation**

Implement:
- `parseLddOutput`
- `stageSandboxRoot`
- `copyFile`
- `buildBwrapArgs`

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add main_test.go sandbox.go
git commit -m "feat: stage sandbox root and bwrap arguments"
```

### Task 3: Create listener inside child net namespace

**Files:**
- Create: `netns_linux.go`
- Modify: `main_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestBuildProxyEnv(t *testing.T) {
	if got := proxyURL(); got != "http://localhost:31111" {
		t.Fatalf("got %q", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./...`
Expected: FAIL with undefined `proxyURL`

- [ ] **Step 3: Write minimal implementation**

Implement:
- `proxyURL`
- `withNetNS`
- `listenInNetNS`

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add main_test.go netns_linux.go
git commit -m "feat: create proxy listener in sandbox net namespace"
```

### Task 4: Implement proxy and orchestration

**Files:**
- Create: `proxy.go`
- Create: `main.go`
- Modify: `main_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestRewriteProxyRequestClearsRequestURI(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	out, err := rewriteProxyRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if out.RequestURI != "" {
		t.Fatalf("RequestURI must be empty, got %q", out.RequestURI)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./...`
Expected: FAIL with undefined `rewriteProxyRequest`

- [ ] **Step 3: Write minimal implementation**

Implement:
- `rewriteProxyRequest`
- proxy handler using `http.Transport`
- orchestration in `main`

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add main.go proxy.go main_test.go
git commit -m "feat: run sandboxed curl through parent proxy"
```

### Task 5: Verify end-to-end behavior

**Files:**
- Modify: `README.md` (optional if needed)

- [ ] **Step 1: Run unit tests**

Run: `go test ./...`
Expected: PASS

- [ ] **Step 2: Run the PoC**

Run: `go run .`
Expected: proxy logs show a forwarded request and `curl -v` exits successfully

- [ ] **Step 3: Inspect behavior**

Confirm:
- `curl` sees `HTTP_PROXY=http://localhost:31111`
- the proxy listener is reachable only because it was bound inside the child net namespace
- outbound HTTP is performed by the parent-side handler

- [ ] **Step 4: Commit**

```bash
git add .
git commit -m "feat: add bubblewrap proxy proof of concept"
```
