package bbox

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestNewMITMCAGeneratesParseableCAPEM(t *testing.T) {
	ca, err := newMITMCA()
	if err != nil {
		t.Fatalf("create MITM CA: %v", err)
	}

	block, _ := pem.Decode(ca.CertPEM())
	if block == nil {
		t.Fatal("expected PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("expected generated certificate to be a CA")
	}
}

func TestIssueLeafCertIncludesRequestedHost(t *testing.T) {
	ca, err := newMITMCA()
	if err != nil {
		t.Fatalf("create MITM CA: %v", err)
	}

	cert, err := ca.LeafForHost("example.com")
	if err != nil {
		t.Fatalf("issue leaf: %v", err)
	}
	if cert.Leaf == nil {
		t.Fatal("expected parsed leaf certificate")
	}
	if len(cert.Leaf.DNSNames) != 1 || cert.Leaf.DNSNames[0] != "example.com" {
		t.Fatalf("unexpected DNS SANs: %#v", cert.Leaf.DNSNames)
	}
}

func TestIssueLeafCertReusesCachedCertificate(t *testing.T) {
	ca, err := newMITMCA()
	if err != nil {
		t.Fatalf("create MITM CA: %v", err)
	}

	first, err := ca.LeafForHost("example.com")
	if err != nil {
		t.Fatalf("issue first leaf: %v", err)
	}
	second, err := ca.LeafForHost("example.com")
	if err != nil {
		t.Fatalf("issue second leaf: %v", err)
	}
	if first != second {
		t.Fatal("expected cached leaf certificate to be reused")
	}
}
