package dockerbuild

import (
	"os"
	"path/filepath"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const testTrustBundlePEM = `-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUftYttXu1HgnSWes70iPcUR7tDV4wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJYmJveC10ZXN0MB4XDTI2MDQwNzIyMzUzNloXDTI2MDQw
ODIyMzUzNlowFDESMBAGA1UEAwwJYmJveC10ZXN0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA5rlKVjTExyPo92Znqk3DqvMfRmOLF/ZxMMgR0LKM6efg
fjZ6vw0WGwpgbM4YeclIMjHN19MgTZmfBowxCajXhWw+NNhIsSZZZ9Oo44bewhgh
Dtx/VEgzZXdlaoHgdQdTvJP8QmXumVsWOEyeIRRUCr+PS8UzoG/XWhgSJNuu3GWI
p+w+pOSVh2RJjfBgbfs3jbUOXMIe5/rJ3v+TKiB+pCRliI1s3OyzqSAxPuBX1HuM
Po6MfReNZproZ/HY2J5YfVF9JLdsLj85wah6AJR94dspFSJglNv6Vup4gjlTSl/e
H0W3yUuHuO6U0q8zDswYYEAlRs0jdXBe1hVkID+cpQIDAQABo1MwUTAdBgNVHQ4E
FgQUuXnLafCzSIl5fnxAifQ+1Th7DyEwHwYDVR0jBBgwFoAUuXnLafCzSIl5fnxA
ifQ+1Th7DyEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEABR5G
4+nxvdepsoLcgWK7Ww4mqMNO5AMhA3BspjGYbKKp0zis+hzQMtFd51A4lqnWuJl5
RLICF5vZ201kmBX0VZf3CtsfdrcHDVefCUEvqqW4szLNl7Cfzu0+YaedaI4JujMC
addvcPgmKn92e99HLGgX4sevzewIW4WLn9Mrhvvwjduo8RIO9D+97I6kp9reaTwl
mlxwYWuxkcq/zrb0fnUYQRu114h/S/bZrgldPADYGCie4Mc0mdVdFEzC9kCfV36W
4Qf5svHwUmfb/w/Q/tZC59VEbk4ZqCApWKAYmhodwzzr1BL94fhIv4X7p7Z60N1v
z4ccCnH2QtqGR13dkQ==
-----END CERTIFICATE-----
`

func TestWritePKCS12Truststore(t *testing.T) {
	t.Run("writes PKCS12 truststore from PEM bundle", func(t *testing.T) {
		stageDir := t.TempDir()

		got, err := writePKCS12Truststore(stageDir, []byte(testTrustBundlePEM))
		if err != nil {
			t.Fatalf("writePKCS12Truststore failed: %v", err)
		}
		if got.Type != bboxJavaTruststoreType {
			t.Fatalf("expected truststore type %q, got %q", bboxJavaTruststoreType, got.Type)
		}
		if got.Password == "" {
			t.Fatal("expected non-empty truststore password")
		}
		if filepath.Base(got.Path) != bboxJavaTruststoreFileName {
			t.Fatalf("expected truststore filename %q, got %q", bboxJavaTruststoreFileName, got.Path)
		}

		encoded, err := os.ReadFile(got.Path)
		if err != nil {
			t.Fatalf("read generated truststore %q: %v", got.Path, err)
		}
		if len(encoded) == 0 {
			t.Fatal("expected non-empty truststore contents")
		}
		decoded, err := pkcs12.DecodeTrustStore(encoded, got.Password)
		if err != nil {
			t.Fatalf("expected generated truststore to decode with returned password: %v", err)
		}
		if len(decoded) == 0 {
			t.Fatal("expected decoded truststore to contain at least one certificate")
		}
	})

	t.Run("fails when bundle has no certificates", func(t *testing.T) {
		_, err := writePKCS12Truststore(t.TempDir(), []byte("not a certificate bundle"))
		if err == nil {
			t.Fatal("expected writePKCS12Truststore to fail for invalid PEM")
		}
	})
}

func TestPrepareBuildInputsStagesJavaTruststoreAndMavenSettings(t *testing.T) {
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "Dockerfile"), []byte("FROM alpine:3.18\nRUN echo test\n"), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}

	trustBundlePath := filepath.Join(cwd, "bbox-trust.pem")
	if err := os.WriteFile(trustBundlePath, []byte(testTrustBundlePEM), 0o644); err != nil {
		t.Fatalf("write trust bundle: %v", err)
	}

	plan, err := PlanForArgs([]string{"build", "."}, []string{
		"BBOX_TRUST_BUNDLE_PATH=" + trustBundlePath,
		"HTTPS_PROXY=http://127.0.0.1:3128",
	}, cwd)
	if err != nil {
		t.Fatalf("PlanForArgs failed: %v", err)
	}
	t.Cleanup(func() {
		cleanupPaths(plan.CleanupPaths)
	})

	stagingDir := argValueForRepeatedFlag(plan.BuildctlArgs, "--local", "bbox_mitm_trust=")
	if stagingDir == "" {
		t.Fatal("expected trust staging dir")
	}
	truststoreInfo, err := os.Stat(filepath.Join(stagingDir, "bbox-truststore.p12"))
	if err != nil {
		t.Fatalf("expected staged JVM truststore: %v", err)
	}
	if truststoreInfo.Size() == 0 {
		t.Fatal("expected staged JVM truststore to be non-empty")
	}
	settingsInfo, err := os.Stat(filepath.Join(stagingDir, "bbox-maven-settings.xml"))
	if err != nil {
		t.Fatalf("expected staged Maven settings: %v", err)
	}
	if settingsInfo.Size() == 0 {
		t.Fatal("expected staged Maven settings to be non-empty")
	}
}
