package bbox

import "testing"

func TestSandboxRunRejectsEmptyArgv(t *testing.T) {
	s := &Sandbox{}
	_, err := s.Run(nil, nil, RunOptions{})
	if err == nil {
		t.Fatal("expected empty argv to fail")
	}
}
