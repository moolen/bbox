package launcherentrypoint

import (
	"os"
	"reflect"
	"testing"
)

func TestParseFlagsRequiresLauncherArgv(t *testing.T) {
	_, _, err := parseFlags([]string{"--launcher-fd", "3"})
	if err == nil {
		t.Fatal("expected missing launcher argv to fail")
	}
}

func TestRunExecsLauncherFromFD(t *testing.T) {
	prev := execLauncherFromFD
	t.Cleanup(func() {
		execLauncherFromFD = prev
	})

	called := false
	execLauncherFromFD = func(fd int, argv, env []string) error {
		called = true
		if fd != 7 {
			t.Fatalf("fd = %d, want 7", fd)
		}
		wantArgv := []string{"bbox-seccomp-launcher", "/bin/true"}
		if !reflect.DeepEqual(argv, wantArgv) {
			t.Fatalf("argv = %v, want %v", argv, wantArgv)
		}
		if !containsString(env, "PATH="+os.Getenv("PATH")) {
			t.Fatalf("expected PATH in environment, got %v", env)
		}
		return nil
	}

	if err := Run([]string{"--launcher-fd", "7", "--", "bbox-seccomp-launcher", "/bin/true"}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected execLauncherFromFD to be called")
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
