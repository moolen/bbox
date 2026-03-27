package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseLddOutput(t *testing.T) {
	input := "\tlibcurl.so.4 => /usr/lib/libcurl.so.4 (0x0)\n\t/lib64/ld-linux-x86-64.so.2 (0x0)\n"
	got := parseLddOutput(input)
	want := []string{"/usr/lib/libcurl.so.4", "/lib64/ld-linux-x86-64.so.2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestBuildBwrapArgsSetsProxyAndNamespaceFlags(t *testing.T) {
	args := buildBwrapArgs("/tmp/root", 3)
	joined := strings.Join(args, " ")
	for _, needle := range []string{
		"--unshare-user",
		"--unshare-net",
		"PARENT_PROXY_FD",
		"HTTP_PROXY",
		"http://localhost:31111",
		"/app/bwrap-go",
		"child-proxy",
	} {
		if !strings.Contains(joined, needle) {
			t.Fatalf("missing %q in %q", needle, joined)
		}
	}
}

func TestProxyURL(t *testing.T) {
	if got := proxyURL(); got != "http://localhost:31111" {
		t.Fatalf("got %q", got)
	}
}

func TestRewriteProxyRequestClearsRequestURI(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	out, err := rewriteProxyRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if out.RequestURI != "" {
		t.Fatalf("RequestURI must be empty, got %q", out.RequestURI)
	}
	if out.URL.String() != "http://example.com" {
		t.Fatalf("unexpected URL %q", out.URL.String())
	}
}

func TestStageSandboxRootCreatesConfig(t *testing.T) {
	root, err := stageSandboxRoot()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	for _, rel := range []string{
		"etc/hosts",
		"etc/nsswitch.conf",
		"usr/bin/curl",
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Fatalf("missing %s: %v", rel, err)
		}
	}
}
