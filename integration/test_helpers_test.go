package integration_test

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func requireSandboxPrereqs(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("bubblewrap sandbox integration test requires linux")
	}
	if _, err := requireTool("bwrap"); err != nil {
		t.Skip(err.Error())
	}
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
