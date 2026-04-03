package integration_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/moolen/bbox"
)

var (
	sharedTLSTestCertOnce sync.Once
	sharedTLSTestCert     tls.Certificate
	sharedTLSTestCertErr  error
)

type networkToolPaths struct {
	curl string
	ping string
	dns  string
	nc   string
}

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

func TestResolveFirstAvailableToolRejectsNonExecutablePath(t *testing.T) {
	dir := t.TempDir()
	nonExecutable := filepath.Join(dir, "dig")
	if err := os.WriteFile(nonExecutable, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := resolveFirstAvailableTool([]string{nonExecutable})
	if err == nil {
		t.Fatal("expected non-executable path to fail")
	}
	if !strings.Contains(err.Error(), "missing required tool") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListenLoopbackPortReturnsErrorWhenUnavailable(t *testing.T) {
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	blocked, err := listenLoopbackPort(port)
	if err == nil {
		if blocked != nil {
			_ = blocked.Close()
		}
		t.Fatal("expected occupied port to fail")
	}
}

func TestShouldSkipTransparentRuntimePortRequirement(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "permission denied",
			err:  &net.OpError{Err: os.NewSyscallError("listen", syscall.EACCES)},
			want: true,
		},
		{
			name: "operation not permitted",
			err:  &net.OpError{Err: os.NewSyscallError("listen", syscall.EPERM)},
			want: true,
		},
		{
			name: "address in use",
			err:  &net.OpError{Err: os.NewSyscallError("listen", syscall.EADDRINUSE)},
			want: true,
		},
		{
			name: "other error",
			err:  errors.New("boom"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldSkipTransparentRuntimePortRequirement(tt.err); got != tt.want {
				t.Fatalf("shouldSkipTransparentRuntimePortRequirement(%v) = %v want %v", tt.err, got, tt.want)
			}
		})
	}
}

func requireSandboxPrereqs(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("bubblewrap sandbox integration test requires linux")
	}
	if _, err := requireTool("bwrap"); err != nil {
		t.Skip(err.Error())
	}
}

func resolveFirstAvailableTool(candidates []string) (string, error) {
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if strings.Contains(candidate, string(filepath.Separator)) {
			info, err := os.Stat(candidate)
			if err != nil {
				continue
			}
			if info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
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

func trustHTTPSServer(t *testing.T, server *httptest.Server) {
	t.Helper()
	if server == nil || server.TLS == nil || len(server.TLS.Certificates) == 0 || len(server.TLS.Certificates[0].Certificate) == 0 {
		t.Fatal("https test server certificate is unavailable")
	}

	certDER := server.TLS.Certificates[0].Certificate[0]
	if _, err := x509.ParseCertificate(certDER); err != nil {
		t.Fatalf("parse https test server certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	bundlePath := filepath.Join(t.TempDir(), "server-root.pem")
	if err := os.WriteFile(bundlePath, certPEM, 0o600); err != nil {
		t.Fatalf("write HTTPS trust bundle: %v", err)
	}

	t.Setenv("SSL_CERT_FILE", bundlePath)
	t.Setenv("SSL_CERT_DIR", "")
}

func buildStaticTestClient(t *testing.T, name string, source string) string {
	t.Helper()
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "main.go")
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatalf("write test client source: %v", err)
	}

	binaryPath := filepath.Join(dir, name)
	cmd := exec.Command("go", "build", "-o", binaryPath, sourcePath)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build test client %s: %v: %s", name, err, string(output))
	}
	return binaryPath
}

func mustPortForServer(t *testing.T, server *httptest.Server) string {
	t.Helper()
	if server == nil || server.Listener == nil {
		t.Fatal("test server listener is unavailable")
	}
	return fmt.Sprintf("%d", server.Listener.Addr().(*net.TCPAddr).Port)
}

func startTransparentHTTPTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()

	server := httptest.NewUnstartedServer(handler)
	server.Listener = mustListenLoopbackPort(t, 80)
	server.Start()
	return server
}

func startTransparentTLSTestServer(t *testing.T, host string, handler http.Handler) *httptest.Server {
	return startTransparentTLSTestServerOnPort(t, host, 443, handler)
}

func startTransparentTLSTestServerOnPort(t *testing.T, host string, port int, handler http.Handler) *httptest.Server {
	t.Helper()
	_ = host

	server := httptest.NewUnstartedServer(handler)
	server.Listener = mustListenLoopbackPort(t, port)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{sharedTLSTestCertificate(t)},
	}
	server.StartTLS()
	return server
}

func startTrustedTLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()

	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{sharedTLSTestCertificate(t)},
	}
	server.StartTLS()
	return server
}

func mustListenLoopbackPort(t *testing.T, port int) net.Listener {
	t.Helper()

	listener, err := listenLoopbackPort(port)
	if err != nil {
		if shouldSkipTransparentRuntimePortRequirement(err) {
			t.Skipf("transparent sandbox integration test requires binding 127.0.0.1:%d: %v", port, err)
		}
		t.Fatalf("transparent sandbox integration test requires binding 127.0.0.1:%d: %v", port, err)
	}
	return listener
}

func requireTransparentRuntimePortsStrict(t *testing.T) {
	t.Helper()

	for _, port := range []int{53, 80, 443} {
		listener, err := listenLoopbackPort(port)
		if err != nil {
			if shouldSkipTransparentRuntimePortRequirement(err) {
				t.Skipf("transparent integration test requires binding 127.0.0.1:%d: %v", port, err)
			}
			t.Fatalf("transparent integration test requires binding 127.0.0.1:%d: %v", port, err)
		}
		_ = listener.Close()
	}
}

func listenLoopbackPort(port int) (net.Listener, error) {
	return net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
}

func shouldSkipTransparentRuntimePortRequirement(err error) bool {
	return errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EADDRINUSE)
}

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

func sharedTLSTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	sharedTLSTestCertOnce.Do(func() {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			sharedTLSTestCertErr = err
			return
		}

		serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			sharedTLSTestCertErr = err
			return
		}

		template := &x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				CommonName: "bbox-integration-test",
			},
			DNSNames:              []string{"localhost", "secure.localhost"},
			IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
		if err != nil {
			sharedTLSTestCertErr = err
			return
		}

		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		})
		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		})

		sharedTLSTestCert, sharedTLSTestCertErr = tls.X509KeyPair(certPEM, keyPEM)
	})

	if sharedTLSTestCertErr != nil {
		t.Fatalf("generate shared test TLS certificate: %v", sharedTLSTestCertErr)
	}
	return sharedTLSTestCert
}
