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

func TestOpenCodeSmokeSkipsLoopbackSetupUnsupported(t *testing.T) {
	t.Parallel()

	output := runOpenCodeSmokeScript(t, "mixed-loopback-unsupported")
	if !strings.Contains(output, "SKIP loopback setup unsupported: proxy-enforce-copy-env") {
		t.Fatalf("expected loopback setup skip in output, got:\n%s", output)
	}
	if !strings.Contains(output, "PASS expected auth failure: transparent-enforce-explicit-env") {
		t.Fatalf("expected non-skipped cases to continue after loopback skip, got:\n%s", output)
	}
}

func TestOpenCodeSmokeFailsWhenAllCasesSkip(t *testing.T) {
	t.Parallel()

	output, err := runOpenCodeSmokeScriptExpectError(t, "loopback-unsupported")
	if err == nil {
		t.Fatalf("expected all-skipped smoke run to fail, output:\n%s", output)
	}
	if !strings.Contains(output, "FAIL all selected opencode smoke cases skipped") {
		t.Fatalf("expected all-skipped failure in output, got:\n%s", output)
	}
}

func TestOpenCodeSmokeUsesSandboxPathOverride(t *testing.T) {
	t.Parallel()

	sandboxPathDir := filepath.Join(t.TempDir(), "sandbox-path")
	if err := os.MkdirAll(sandboxPathDir, 0o755); err != nil {
		t.Fatalf("mkdir sandbox path dir: %v", err)
	}
	for _, tool := range []string{"awk", "grep"} {
		target, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("resolve %s: %v", tool, err)
		}
		if err := os.Symlink(target, filepath.Join(sandboxPathDir, tool)); err != nil {
			t.Fatalf("symlink %s: %v", tool, err)
		}
	}

	output, err := runOpenCodeSmokeScriptWithEnv(t, "auth-failure", map[string]string{
		"OPENCODE_SMOKE_PATH_VALUE": sandboxPathDir,
		"EXPECT_BBOX_PATH":          sandboxPathDir,
	})
	if err != nil {
		t.Fatalf("run opencode smoke script with sandbox path override: %v\n%s", err, output)
	}
	if !strings.Contains(output, "PASS expected auth failure: transparent-enforce-explicit-env") {
		t.Fatalf("expected explicit PATH case to succeed, got:\n%s", output)
	}
}

func runOpenCodeSmokeScript(t *testing.T, fakeBBoxMode string) string {
	t.Helper()

	output, err := runOpenCodeSmokeScriptWithEnv(t, fakeBBoxMode, nil)
	if err != nil {
		t.Fatalf("run opencode smoke script: %v\n%s", err, output)
	}
	return output
}

func runOpenCodeSmokeScriptExpectError(t *testing.T, fakeBBoxMode string) (string, error) {
	t.Helper()
	return runOpenCodeSmokeScriptWithEnv(t, fakeBBoxMode, nil)
}

func runOpenCodeSmokeScriptWithEnv(t *testing.T, fakeBBoxMode string, extraEnv map[string]string) (string, error) {
	t.Helper()

	root := moduleRoot(t)
	fakeBinDir := filepath.Join(t.TempDir(), "fake-bin")
	if err := os.MkdirAll(fakeBinDir, 0o755); err != nil {
		t.Fatalf("mkdir fake bin dir: %v", err)
	}

	writeExecutableScript(t, filepath.Join(fakeBinDir, "bbox"), fakeBBoxScript)
	writeExecutableScript(t, filepath.Join(fakeBinDir, "timeout"), fakeTimeoutScript)
	writeExecutableScript(t, filepath.Join(fakeBinDir, "opencode"), noopToolScript("opencode"))
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
		"OPENCODE_SMOKE_SKIP_SUBID_CHECK=1",
		"PATH="+fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	for key, value := range extraEnv {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
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
config_path=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--config" ]; then
    config_path="$arg"
    break
  fi
  prev="$arg"
done
[ -n "$config_path" ] || config_path="$PWD/bbox.yaml"
[ -f "$config_path" ] || {
  echo "missing bbox config at $config_path" >&2
  exit 91
}

case_name="$(awk -F': ' '/^name:/ {print $2; exit}' "$config_path")"
[ -n "$case_name" ] || {
  echo "missing case name in $config_path" >&2
  exit 92
}

case_root="$(awk -F': ' '/^[[:space:]]+source:/ {print $2; exit}' "$config_path")"
[ -n "$case_root" ] || {
  echo "missing case root source in $config_path" >&2
  exit 93
}

opencode_config="$case_root/home/.config/opencode/opencode.json"
[ -f "$opencode_config" ] || {
  echo "missing opencode config at $opencode_config" >&2
  exit 94
}
grep -q '"openai"' "$opencode_config" || { echo "missing openai provider config" >&2; exit 95; }
grep -q '"npm": "@ai-sdk/openai"' "$opencode_config" || { echo "missing bundled openai provider package" >&2; exit 96; }
grep -q '"env": \["OPENAI_API_KEY"\]' "$opencode_config" || { echo "missing openai env config" >&2; exit 97; }
grep -q '"model": "openai/gpt-4.1-mini"' "$opencode_config" || { echo "missing smoke model config" >&2; exit 98; }
! grep -q 'OPENAI_API_KEY=' "$config_path" || { echo "unexpected explicit OPENAI_API_KEY env" >&2; exit 99; }

if [ -n "${EXPECT_BBOX_PATH:-}" ] && [ "${PATH:-}" != "$EXPECT_BBOX_PATH" ]; then
  echo "unexpected bbox PATH: ${PATH:-}" >&2
  exit 118
fi

printf 'FAKE_BBOX %s\n' "$case_name"

case "$case_name" in
  proxy-enforce-copy-env)
    grep -q 'traffic_mode: proxy' "$config_path" || { echo "missing proxy mode" >&2; exit 93; }
    grep -q 'policy_mode: enforce' "$config_path" || { echo "missing enforce mode" >&2; exit 100; }
    grep -q 'copy_env:' "$config_path" || { echo "missing copy_env block" >&2; exit 101; }
    ;;
  transparent-enforce-explicit-env)
    grep -q 'traffic_mode: transparent' "$config_path" || { echo "missing transparent mode" >&2; exit 102; }
    grep -q 'env:' "$config_path" || { echo "missing env block" >&2; exit 103; }
    grep -q 'HOME=' "$config_path" || { echo "missing HOME env" >&2; exit 104; }
    if [ -n "${EXPECT_BBOX_PATH:-}" ]; then
      grep -q "PATH=$EXPECT_BBOX_PATH" "$config_path" || { echo "missing expected explicit PATH override" >&2; exit 117; }
    fi
    ;;
  proxy-audit-copy-env)
    grep -q 'policy_mode: audit' "$config_path" || { echo "missing audit mode" >&2; exit 105; }
    ;;
  proxy-enforce-docker-build|transparent-audit-docker-build)
    grep -q 'docker_build:' "$config_path" || { echo "missing docker_build block" >&2; exit 106; }
    grep -q 'buildkitd_path:' "$config_path" || { echo "missing buildkitd_path" >&2; exit 107; }
    grep -q 'buildctl_path:' "$config_path" || { echo "missing buildctl_path" >&2; exit 108; }
    grep -q 'runc_path:' "$config_path" || { echo "missing runc_path" >&2; exit 109; }
    grep -q 'podman_path:' "$config_path" || { echo "missing podman_path" >&2; exit 110; }
    grep -q 'newuidmap_path:' "$config_path" || { echo "missing newuidmap_path" >&2; exit 111; }
    grep -q 'newgidmap_path:' "$config_path" || { echo "missing newgidmap_path" >&2; exit 112; }
    ;;
esac

joined_args="$*"
printf '%s' "$joined_args" | grep -q -- '--config ' || {
  echo "expected bbox to receive --config, got: $joined_args" >&2
  exit 107
}
printf '%s' "$joined_args" | grep -q -- '-- opencode run ' || {
  echo "expected bbox to receive opencode run argv, got: $joined_args" >&2
  exit 109
}

case "$mode" in
  auth-failure)
    echo "OpenAI API key is missing. Pass it using the 'apiKey' parameter or the OPENAI_API_KEY environment variable." >&2
    exit 0
    ;;
  success)
    echo "OK"
    exit 0
    ;;
  loopback-unsupported)
    echo "start sandbox helper: read bbox-bridge-parent: connection reset by peer: bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted" >&2
    exit 1
    ;;
  mixed-loopback-unsupported)
    if [ "$case_name" = "proxy-enforce-copy-env" ]; then
      echo "start sandbox helper: read bbox-bridge-parent: connection reset by peer: bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted" >&2
      exit 1
    fi
    echo "OpenAI API key is missing. Pass it using the 'apiKey' parameter or the OPENAI_API_KEY environment variable." >&2
    exit 0
    ;;
  *)
    echo "unexpected fake bbox mode: $mode" >&2
    exit 110
    ;;
esac
`
