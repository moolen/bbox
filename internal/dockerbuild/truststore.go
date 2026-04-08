package dockerbuild

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const (
	bboxJavaTruststoreFileName = "bbox-truststore.p12"
	bboxJavaTruststorePassword = pkcs12.DefaultPassword
	bboxJavaTruststoreType     = "PKCS12"
	bboxMavenSettingsFileName  = "bbox-maven-settings.xml"
)

type generatedTruststore struct {
	Path     string
	Password string
	Type     string
}

func writePKCS12Truststore(stageDir string, pemBundle []byte) (generatedTruststore, error) {
	certs, err := parseTrustBundleCertificates(pemBundle)
	if err != nil {
		return generatedTruststore{}, err
	}

	encoded, err := pkcs12.LegacyDES.EncodeTrustStore(certs, bboxJavaTruststorePassword)
	if err != nil {
		return generatedTruststore{}, fmt.Errorf("encode PKCS#12 truststore: %w", err)
	}

	path := filepath.Join(stageDir, bboxJavaTruststoreFileName)
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		return generatedTruststore{}, fmt.Errorf("write PKCS#12 truststore %s: %w", path, err)
	}

	return generatedTruststore{
		Path:     path,
		Password: bboxJavaTruststorePassword,
		Type:     bboxJavaTruststoreType,
	}, nil
}

func parseTrustBundleCertificates(pemBundle []byte) ([]*x509.Certificate, error) {
	remaining := pemBundle
	certs := make([]*x509.Certificate, 0, 1)

	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			if len(bytes.TrimSpace(remaining)) == 0 {
				break
			}
			return nil, fmt.Errorf("parse PEM trust bundle: invalid PEM data")
		}
		remaining = rest

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PEM certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("parse PEM trust bundle: no certificates found")
	}
	return certs, nil
}
