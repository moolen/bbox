package integration_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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
	"sync"
	"testing"
	"time"
)

var (
	sharedTLSTestCertOnce sync.Once
	sharedTLSTestCert     tls.Certificate
	sharedTLSTestCertErr  error
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

func startTransparentHTTPTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()

	server := httptest.NewUnstartedServer(handler)
	server.Listener = mustListenLoopbackPort(t, 80)
	server.Start()
	return server
}

func startTransparentTLSTestServer(t *testing.T, host string, handler http.Handler) *httptest.Server {
	t.Helper()
	_ = host

	server := httptest.NewUnstartedServer(handler)
	server.Listener = mustListenLoopbackPort(t, 443)
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

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("transparent sandbox integration test requires binding %s: %v", addr, err)
	}
	return listener
}

func requireTransparentRuntimePorts(t *testing.T) {
	t.Helper()

	for _, port := range []int{53, 80, 443} {
		listener := mustListenLoopbackPort(t, port)
		_ = listener.Close()
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
