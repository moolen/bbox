package main

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReadDomainListFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowed.txt")
	content := strings.Join([]string{
		"",
		"# comment",
		"example.com",
		"  *.github.com  ",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := readDomainListFile(path)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"example.com", "*.github.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestDomainPatternFromEntry(t *testing.T) {
	tests := []struct {
		entry string
		want  string
	}{
		{entry: "example.com", want: `^example[.]com$`},
		{entry: "*.github.com", want: `^([^.]+[.])+github[.]com$`},
	}

	for _, tt := range tests {
		t.Run(tt.entry, func(t *testing.T) {
			got, err := domainPatternFromEntry(tt.entry)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestParseMountSpec(t *testing.T) {
	got, err := parseMountSpec("/host/path:/sandbox/path", false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != "/host/path" || got.Target != "/sandbox/path" || got.ReadOnly {
		t.Fatalf("unexpected mount: %#v", got)
	}
}

func TestBuildConfigDefaultsMountsCurrentWorkingDirectory(t *testing.T) {
	cwd := t.TempDir()
	cfg, err := buildConfig(cliOptions{}, []string{"bash", "-lc", "pwd"}, cwd, []string{"HOME=/tmp/home", "FOO=bar"})
	if err != nil {
		t.Fatal(err)
	}

	if cfg.sandbox.WorkDir != cwd {
		t.Fatalf("unexpected workdir: got %q want %q", cfg.sandbox.WorkDir, cwd)
	}
	if len(cfg.sandbox.Mounts) != 1 {
		t.Fatalf("expected exactly one default mount, got %d", len(cfg.sandbox.Mounts))
	}
	if cfg.sandbox.Mounts[0].Source != cwd || cfg.sandbox.Mounts[0].Target != cwd || cfg.sandbox.Mounts[0].ReadOnly {
		t.Fatalf("unexpected default mount: %#v", cfg.sandbox.Mounts[0])
	}
	if len(cfg.argv) == 0 || cfg.argv[0] != "bash" {
		t.Fatalf("unexpected argv: %v", cfg.argv)
	}
	if len(cfg.sandbox.Binaries) == 0 || cfg.sandbox.Binaries[0] != "bash" {
		t.Fatalf("expected payload binary to be staged first, got %v", cfg.sandbox.Binaries)
	}
	if !containsString(cfg.sandbox.Env, "FOO=bar") {
		t.Fatalf("expected inherited env in sandbox env, got %v", cfg.sandbox.Env)
	}
}

func TestRootCommandRejectsMissingPayload(t *testing.T) {
	cmd := newRootCommand(commandDeps{
		stdout: io.Discard,
		stderr: io.Discard,
		run: func(runConfig) error {
			t.Fatal("did not expect runner to be called")
			return nil
		},
	})
	cmd.SetArgs(nil)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected missing payload to fail")
	}
	if !strings.Contains(err.Error(), "payload command required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildConfigTransparentModeRequiresMITM(t *testing.T) {
	_, err := buildConfig(cliOptions{trafficMode: "transparent"}, []string{"curl"}, t.TempDir(), nil)
	if err == nil {
		t.Fatal("expected transparent mode without mitm to fail")
	}
	if !strings.Contains(err.Error(), "--mitm") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildConfigClearEnvSkipsInheritedEnv(t *testing.T) {
	cfg, err := buildConfig(cliOptions{
		clearEnv: true,
		env:      []string{"FOO=bar"},
	}, []string{"bash"}, t.TempDir(), []string{"SECRET=value"})
	if err != nil {
		t.Fatal(err)
	}
	if containsString(cfg.sandbox.Env, "SECRET=value") {
		t.Fatalf("did not expect inherited env, got %v", cfg.sandbox.Env)
	}
	if !containsString(cfg.sandbox.Env, "FOO=bar") {
		t.Fatalf("expected explicit env override, got %v", cfg.sandbox.Env)
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
