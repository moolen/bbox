package bbox

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

type mitmCA struct {
	mu         sync.Mutex
	certPEM    []byte
	certDER    []byte
	cert       *x509.Certificate
	privateKey ed25519.PrivateKey
	leafCache  map[string]*tls.Certificate
}

func newMITMCA() (*mitmCA, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate MITM CA key: %w", err)
	}

	serialNumber, err := randomSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generate MITM CA serial: %w", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "bbox ephemeral MITM CA"},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(7 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("create MITM CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse MITM CA certificate: %w", err)
	}

	return &mitmCA{
		certPEM:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		certDER:    certDER,
		cert:       cert,
		privateKey: privateKey,
		leafCache:  make(map[string]*tls.Certificate),
	}, nil
}

func (c *mitmCA) CertPEM() []byte {
	if c == nil || len(c.certPEM) == 0 {
		return nil
	}
	out := make([]byte, len(c.certPEM))
	copy(out, c.certPEM)
	return out
}

func (c *mitmCA) LeafForHost(host string) (*tls.Certificate, error) {
	if c == nil {
		return nil, fmt.Errorf("MITM CA is required")
	}

	normalizedHost := strings.ToLower(strings.TrimSpace(host))
	if normalizedHost == "" {
		return nil, fmt.Errorf("leaf host is required")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if cert := c.leafCache[normalizedHost]; cert != nil {
		return cert, nil
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key for %q: %w", normalizedHost, err)
	}
	serialNumber, err := randomSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generate leaf serial for %q: %w", normalizedHost, err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: normalizedHost},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(normalizedHost); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{normalizedHost}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, c.cert, publicKey, c.privateKey)
	if err != nil {
		return nil, fmt.Errorf("create leaf certificate for %q: %w", normalizedHost, err)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate for %q: %w", normalizedHost, err)
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER, c.certDER},
		PrivateKey:  privateKey,
		Leaf:        leaf,
	}
	c.leafCache[normalizedHost] = cert
	return cert, nil
}

func (c *mitmCA) LeafPEMForHost(host string) ([]byte, []byte, error) {
	cert, err := c.LeafForHost(host)
	if err != nil {
		return nil, nil, err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal leaf private key for %q: %w", host, err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Certificate[0],
	})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})
	return certPEM, keyPEM, nil
}

func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}
