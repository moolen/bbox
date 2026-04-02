package integration_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/moolen/bbox"
)

func TestConnectTunnelUsesDifferentConnectPolicies(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("bubblewrap sandbox integration test requires linux")
	}
	if _, err := requireTool("bwrap"); err != nil {
		t.Skip(err.Error())
	}
	curlPath, err := requireTool("curl")
	if err != nil {
		t.Skip(err.Error())
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ok" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("connect tunneled through bbox"))
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("close manager: %v", err)
		}
	}()

	port := server.Listener.Addr().(*net.TCPAddr).Port

	allowed, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "allowed-connect",
		Binaries: []string{curlPath},
		Policy: bbox.NetworkPolicy{
			Rules: []bbox.PolicyRule{
				{
					HostPatterns: []string{`^127[.]0[.]0[.]1$`},
					ConnectPorts: []string{strconv.Itoa(port)},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("create allowed sandbox: %v", err)
	}
	defer func() {
		if err := allowed.Close(); err != nil {
			t.Fatalf("close allowed sandbox: %v", err)
		}
	}()

	denied, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "denied-connect",
		Binaries: []string{curlPath},
		Policy: bbox.NetworkPolicy{
			Rules: []bbox.PolicyRule{
				{
					HostPatterns: []string{`^127[.]0[.]0[.]1$`},
					ConnectPorts: []string{"443"},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("create denied sandbox: %v", err)
	}
	defer func() {
		if err := denied.Close(); err != nil {
			t.Fatalf("close denied sandbox: %v", err)
		}
	}()

	targetURL := fmt.Sprintf("http://127.0.0.1:%d/ok", port)

	allowedResult, err := allowed.Run(ctx, []string{
		curlPath,
		"--proxytunnel",
		"-sS",
		"-o", "-",
		"-w", "\n%{http_code}\n",
		targetURL,
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("expected allowed tunnel to succeed, got error: %v", err)
	}
	if allowedResult == nil {
		t.Fatal("expected allowed sandbox result")
	}
	if allowedResult.ExitCode != 0 {
		t.Fatalf("expected allowed tunnel exit code 0, got %d stderr=%q", allowedResult.ExitCode, string(allowedResult.Stderr))
	}
	if got := strings.TrimSpace(string(allowedResult.Stdout)); got != "connect tunneled through bbox\n200" {
		t.Fatalf("unexpected allowed tunnel stdout: %q", got)
	}

	deniedResult, err := denied.Run(ctx, []string{
		curlPath,
		"--proxytunnel",
		"-sS",
		"-o", "-",
		"-w", "\n%{http_code}\n",
		targetURL,
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("expected denied sandbox run transport to complete, got error: %v", err)
	}
	if deniedResult == nil {
		t.Fatal("expected denied sandbox result")
	}
	if deniedResult.ExitCode == 0 {
		t.Fatalf("expected denied tunnel to fail, got exit code 0 stdout=%q stderr=%q", string(deniedResult.Stdout), string(deniedResult.Stderr))
	}
	deniedCombined := strings.ToLower(string(deniedResult.Stdout) + "\n" + string(deniedResult.Stderr))
	if !strings.Contains(deniedCombined, "403") {
		t.Fatalf("expected denied tunnel stderr to report a CONNECT 403, got stdout=%q stderr=%q", string(deniedResult.Stdout), string(deniedResult.Stderr))
	}
	if strings.Contains(deniedCombined, "connect tunneled through bbox") {
		t.Fatalf("expected denied tunnel output to exclude success body, got stdout=%q stderr=%q", string(deniedResult.Stdout), string(deniedResult.Stderr))
	}
}

func TestProxyModeHTTPSConnectDoesNotMITM(t *testing.T) {
	requireSandboxPrereqs(t)

	server := startTrustedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ok" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("https tunneled through bbox"))
	}))
	defer server.Close()

	if server.TLS == nil || len(server.TLS.Certificates) == 0 || len(server.TLS.Certificates[0].Certificate) == 0 {
		t.Fatal("https test server certificate is unavailable")
	}

	serverCert, err := x509.ParseCertificate(server.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse https test server certificate: %v", err)
	}

	clientPath := buildStaticTestClient(t, "https-proxy-client", `
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

func main() {
	targetURL := os.Getenv("BBOX_TEST_URL")
	if targetURL == "" {
		fmt.Fprintln(os.Stderr, "missing BBOX_TEST_URL")
		os.Exit(2)
	}
	caPEM := os.Getenv("BBOX_TEST_CA_PEM")
	if caPEM == "" {
		fmt.Fprintln(os.Stderr, "missing BBOX_TEST_CA_PEM")
		os.Exit(2)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		fmt.Fprintln(os.Stderr, "append cert")
		os.Exit(2)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse(os.Getenv("HTTPS_PROXY"))
			},
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("%s\n%d\n", string(body), resp.StatusCode)
}
`)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("close manager: %v", err)
		}
	}()

	port := mustPortForServer(t, server)
	sandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "proxy-mode-https-tunnel",
		Binaries: []string{clientPath},
		Mounts: []bbox.Mount{
			{Source: filepath.Dir(clientPath), Target: "/workspace", ReadOnly: true},
		},
		Policy: bbox.NetworkPolicy{
			Rules: []bbox.PolicyRule{
				{
					HostPatterns: []string{`^127[.]0[.]0[.]1$`},
					ConnectPorts: []string{port},
				},
			},
		},
		Env: []string{
			"BBOX_TEST_URL=" + server.URL + "/ok",
			"BBOX_TEST_CA_PEM=" + string(pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: serverCert.Raw,
			})),
		},
	})
	if err != nil {
		t.Fatalf("create sandbox: %v", err)
	}
	defer func() {
		if err := sandbox.Close(); err != nil {
			t.Fatalf("close sandbox: %v", err)
		}
	}()

	result, err := sandbox.Run(ctx, []string{"/workspace/" + filepath.Base(clientPath)}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("expected HTTPS proxy tunnel to succeed, got error: %v", err)
	}
	if result == nil {
		t.Fatal("expected sandbox run result")
	}
	if result.ExitCode != 0 {
		t.Fatalf("expected HTTPS proxy tunnel exit code 0, got %d stdout=%q stderr=%q", result.ExitCode, string(result.Stdout), string(result.Stderr))
	}
	if got := strings.TrimSpace(string(result.Stdout)); got != "https tunneled through bbox\n200" {
		t.Fatalf("unexpected HTTPS tunnel stdout: %q", got)
	}
}
