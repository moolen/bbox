package dockerbuild

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	buildkitSocketPath = "/tmp/bbox-buildkitd.sock"
	buildkitRootPath   = "/tmp/bbox-buildkitd-root"
	buildkitLogPath    = "/tmp/bbox-buildkitd.log"
)

type cliExecutor interface {
	Run() error
}

type cliExecutorFunc func() error

func (fn cliExecutorFunc) Run() error {
	return fn()
}

type buildkitExecutor struct {
	plan   Plan
	env    []string
	stdout io.Writer
	stderr io.Writer
}

func newBuildkitExecutor(plan Plan, env []string, stdout io.Writer, stderr io.Writer) cliExecutor {
	return buildkitExecutor{
		plan:   plan,
		env:    append([]string(nil), env...),
		stdout: stdout,
		stderr: stderr,
	}
}

func (e buildkitExecutor) Run() error {
	_ = os.Remove(e.plan.OutputPath)
	builderEnv := withBuilderRuntimeEnv(e.env)
	if err := ensureBuildkitd(builderEnv); err != nil {
		return err
	}

	buildctlArgs := append([]string{"--addr", "unix://" + buildkitSocketPath}, e.plan.BuildctlArgs...)
	cmd := exec.Command("buildctl", buildctlArgs...)
	cmd.Env = builderEnv
	cmd.Stdout = e.stdout
	cmd.Stderr = e.stderr
	if err := cmd.Run(); err != nil {
		_ = os.Remove(e.plan.OutputPath)
		return err
	}
	_, _ = fmt.Fprintf(e.stdout, "bbox docker build output: %s\n", e.plan.OutputPath)
	return nil
}

func ensureBuildkitd(env []string) error {
	if buildkitdReady() {
		return nil
	}
	_ = os.Remove(buildkitSocketPath)
	if err := os.MkdirAll(buildkitRootPath, 0o755); err != nil {
		return fmt.Errorf("create buildkit root: %w", err)
	}

	logFile, err := os.OpenFile(buildkitLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open buildkit log: %w", err)
	}
	defer logFile.Close()

	cmd := exec.Command(
		"buildkitd",
		"--rootless",
		"--addr", "unix://"+buildkitSocketPath,
		"--root", buildkitRootPath,
		"--oci-worker-snapshotter=native",
		"--oci-worker-no-process-sandbox",
	)
	cmd.Env = env
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start buildkitd: %w", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if buildkitdReady() {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("buildkitd did not become ready; see %s", buildkitLogPath)
}

func withBuilderRuntimeEnv(env []string) []string {
	out := filterBuilderControlEnv(env)
	if value, ok := lookupEnvValue(env, bboxProxyArgsOnlyEnvKey); ok && strings.TrimSpace(value) == "1" {
		out = filterBuilderProxyEnv(out)
	}
	godebug, ok := lookupEnvValue(out, "GODEBUG")
	if !ok || strings.TrimSpace(godebug) == "" {
		return append(out, "GODEBUG=netdns=cgo")
	}
	if strings.Contains(godebug, "netdns=") {
		return out
	}
	return append(out, "GODEBUG="+godebug+",netdns=cgo")
}

func buildkitdReady() bool {
	conn, err := net.DialTimeout("unix", buildkitSocketPath, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func filterBuilderProxyEnv(env []string) []string {
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, ok := splitEnvEntry(entry)
		if !ok {
			continue
		}
		switch key {
		case "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy":
			continue
		default:
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func filterBuilderControlEnv(env []string) []string {
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, ok := splitEnvEntry(entry)
		if !ok {
			continue
		}
		if key == bboxProxyArgsOnlyEnvKey {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func splitEnvEntry(entry string) (string, string, bool) {
	if entry == "" {
		return "", "", false
	}
	split := strings.IndexByte(entry, '=')
	if split < 0 {
		return entry, "", true
	}
	return entry[:split], entry[split+1:], true
}
