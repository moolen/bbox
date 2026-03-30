package embeddedlauncher

import "testing"

func TestForRuntimeArchReturnsLauncherBytes(t *testing.T) {
	payload, err := ForRuntimeArch()
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) == 0 {
		t.Fatal("expected embedded launcher bytes")
	}
}
