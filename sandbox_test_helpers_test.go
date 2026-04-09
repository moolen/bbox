package bbox

import (
	"errors"
	"strings"
	"testing"
)

func isLoopbackSetupUnsupported(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "loopback: Failed RTM_NEWADDR: Operation not permitted")
}

func skipIfLoopbackSetupUnsupported(t *testing.T, err error) {
	t.Helper()

	if isLoopbackSetupUnsupported(err) {
		t.Skipf("sandbox test requires loopback RTM_NEWADDR support inside bubblewrap: %v", err)
	}
}

func TestIsLoopbackSetupUnsupported(t *testing.T) {
	t.Run("matches bubblewrap RTM_NEWADDR permission error", func(t *testing.T) {
		err := errors.New("start sandbox helper: read bbox-bridge-parent: connection reset by peer: bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted")

		if !isLoopbackSetupUnsupported(err) {
			t.Fatalf("expected loopback setup error to be recognized")
		}
	})

	t.Run("ignores unrelated errors", func(t *testing.T) {
		err := errors.New("start sandbox helper: exited with status 1")

		if isLoopbackSetupUnsupported(err) {
			t.Fatalf("expected unrelated error to be ignored")
		}
	})
}
