package bbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenCodeSmokeAcceptsCredentialFailure(t *testing.T) {
	t.Parallel()

	output := runOpenCodeSmokeScript(t, "auth-failure")
	if !strings.Contains(output, "PASS expected auth failure: proxy-enforce-copy-env") {
		t.Fatalf("expected auth-failure classification in output, got:\n%s", output)
	}
}

func TestOpenCodeSmokeRejectsUnexpectedSuccess(t *testing.T) {
	t.Parallel()

	output, err := runOpenCodeSmokeScriptExpectError(t, "success")
	if err == nil {
		t.Fatalf("expected script to fail on unexpected success, output:\n%s", output)
	}
	if !strings.Contains(output, "FAIL unexpected success: proxy-enforce-copy-env") {
		t.Fatalf("expected unexpected-success failure in output, got:\n%s", output)
	}
}

func TestOpenCodeSmokeBuilderCaseWritesDockerBuildConfig(t *testing.T) {
	t.Parallel()

	output := runOpenCodeSmokeScript(t, "auth-failure")
	for _, want := range []string{
		"RUN proxy-enforce-docker-build",
		"RUN transparent-audit-docker-build",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected %q in output, got:\n%s", want, output)
		}
	}
}

func runOpenCodeSmokeScript(t *testing.T, fakeBBoxMode string) string {
	t.Helper()

	output, err := runOpenCodeSmokeScriptExpectError(t, fakeBBoxMode)
	if err != nil {
		t.Fatalf("run opencode smoke script: %v\n%s", err, output)
	}
	return output
}

func runOpenCodeSmokeScriptExpectError(t *testing.T, fakeBBoxMode string) (string, error) {
	t.Helper()

	root := moduleRoot(t)
	fakeBinDir := filepath.Join(t.TempDir(), "fake-bin")
	if err := os.MkdirAll(fakeBinDir, 0o755); err != nil {
		t.Fatalf("mkdir fake bin dir: %v", err)
	}

	writeExecutableScript(t, filepath.Join(fakeBinDir, "bbox"), fakeBBoxScript)
	writeExecutableScript(t, filepath.Join(fakeBinDir, "timeout"), fakeTimeoutScript)
	writeExecutableScript(t, filepath.Join(fakeBinDir, "buildkitd"), noopToolScript("buildkitd"))
	writeExecutableScript(t, filepath.Join(fakeBinDir, "buildctl"), noopToolScript("buildctl"))
	writeExecutableScript(t, filepath.Join(fakeBinDir, "runc"), noopToolScript("runc"))
	writeExecutableScript(t, filepath.Join(fakeBinDir, "podman"), noopToolScript("podman"))
	writeExecutableScript(t, filepath.Join(fakeBinDir, "newuidmap"), noopToolScript("newuidmap"))
	writeExecutableScript(t, filepath.Join(fakeBinDir, "newgidmap"), noopToolScript("newgidmap"))

	cmd := exec.Command("sh", "./scripts/opencode-smoke.sh")
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"CI=1",
		"FAKE_BBOX_MODE="+fakeBBoxMode,
		"BBOX_BIN="+filepath.Join(fakeBinDir, "bbox"),
		"TIMEOUT_BIN="+filepath.Join(fakeBinDir, "timeout"),
		"PATH="+fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func writeExecutableScript(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write script %s: %v", path, err)
	}
}

func noopToolScript(name string) string {
	return "#!/bin/sh\n" +
		"echo \"" + name + "\" >/dev/null\n"
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return root
}

const fakeTimeoutScript = `#!/bin/sh
set -eu
if [ "$#" -lt 2 ]; then
  echo "timeout wrapper expected duration and command" >&2
  exit 2
fi
shift
exec "$@"
`

const fakeBBoxScript = `#!/bin/sh
set -eu
mode="${FAKE_BBOX_MODE:-auth-failure}"
config_path="$PWD/bbox.yaml"
[ -f "$config_path" ] || {
  echo "missing bbox.yaml in $PWD" >&2
  exit 91
}

case_name="$(awk -F': ' '/^name:/ {print $2; exit}' "$config_path")"
[ -n "$case_name" ] || {
  echo "missing case name in $config_path" >&2
  exit 92
}

printf 'FAKE_BBOX %s\n' "$case_name"

case "$case_name" in
  proxy-enforce-copy-env)
    grep -q 'traffic_mode: proxy' "$config_path" || { echo "missing proxy mode" >&2; exit 93; }
    grep -q 'policy_mode: enforce' "$config_path" || { echo "missing enforce mode" >&2; exit 94; }
    grep -q 'copy_env:' "$config_path" || { echo "missing copy_env block" >&2; exit 95; }
    ;;
  transparent-enforce-explicit-env)
    grep -q 'traffic_mode: transparent' "$config_path" || { echo "missing transparent mode" >&2; exit 96; }
    grep -q 'env:' "$config_path" || { echo "missing env block" >&2; exit 97; }
    grep -q 'HOME=' "$config_path" || { echo "missing HOME env" >&2; exit 98; }
    ;;
  proxy-audit-copy-env)
    grep -q 'policy_mode: audit' "$config_path" || { echo "missing audit mode" >&2; exit 99; }
    ;;
  proxy-enforce-docker-build|transparent-audit-docker-build)
    grep -q 'docker_build:' "$config_path" || { echo "missing docker_build block" >&2; exit 100; }
    grep -q 'buildkitd_path:' "$config_path" || { echo "missing buildkitd_path" >&2; exit 101; }
    grep -q 'buildctl_path:' "$config_path" || { echo "missing buildctl_path" >&2; exit 102; }
    grep -q 'runc_path:' "$config_path" || { echo "missing runc_path" >&2; exit 103; }
    grep -q 'podman_path:' "$config_path" || { echo "missing podman_path" >&2; exit 104; }
    grep -q 'newuidmap_path:' "$config_path" || { echo "missing newuidmap_path" >&2; exit 105; }
    grep -q 'newgidmap_path:' "$config_path" || { echo "missing newgidmap_path" >&2; exit 106; }
    ;;
esac

joined_args="$*"
printf '%s' "$joined_args" | grep -q -- '-- opencode run ' || {
  echo "expected bbox to receive opencode run argv, got: $joined_args" >&2
  exit 107
}

case "$mode" in
  auth-failure)
    echo "missing credentials for provider openai" >&2
    exit 1
    ;;
  success)
    echo "OK"
    exit 0
    ;;
  *)
    echo "unexpected fake bbox mode: $mode" >&2
    exit 108
    ;;
esac
`
