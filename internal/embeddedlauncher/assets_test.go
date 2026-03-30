package embeddedlauncher

import "testing"

func TestForArchReturnsLauncherBytesForSupportedArchitectures(t *testing.T) {
	for _, goarch := range []string{"amd64", "arm64"} {
		t.Run(goarch, func(t *testing.T) {
			payload, err := ForArch(goarch)
			if err != nil {
				t.Fatalf("ForArch(%q) returned error: %v", goarch, err)
			}
			if len(payload) == 0 {
				t.Fatalf("ForArch(%q) returned empty payload", goarch)
			}
		})
	}
}

func TestForRuntimeArchReturnsLauncherBytes(t *testing.T) {
	payload, err := ForRuntimeArch()
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) == 0 {
		t.Fatal("expected embedded launcher bytes")
	}
}
