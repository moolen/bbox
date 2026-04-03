package bbox

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParseLddOutputFindsAbsolutePaths(t *testing.T) {
	input := "\tlibcurl.so.4 => /usr/lib/libcurl.so.4 (0x0)\n\t/lib64/ld-linux-x86-64.so.2 (0x0)\n"
	got := parseLddOutput(input)
	if len(got) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(got))
	}
}

func TestSandboxPathInRootMapsAbsolutePathUnderRoot(t *testing.T) {
	root := t.TempDir()
	got, err := sandboxPathInRoot(root, "/etc/hosts")
	if err != nil {
		t.Fatalf("sandboxPathInRoot failed: %v", err)
	}
	want := filepath.Join(root, "etc", "hosts")
	if got != want {
		t.Fatalf("unexpected mapped path: got %q want %q", got, want)
	}
}

func TestSandboxPathInRootRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	if _, err := sandboxPathInRoot(root, "../etc/shadow"); err == nil {
		t.Fatal("expected traversal path to be rejected")
	}
}

func TestCopyFileToPathStagesAbsoluteSandboxPathUnderRoot(t *testing.T) {
	root := t.TempDir()
	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "source.txt")
	wantContent := "hello from source\n"
	if err := os.WriteFile(sourcePath, []byte(wantContent), 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	outsideDir := t.TempDir()
	sandboxPath := filepath.Join(outsideDir, "nested", "dest.txt")
	expectedDest := filepath.Join(root, strings.TrimPrefix(filepath.Clean(sandboxPath), string(filepath.Separator)))

	if err := copyFileToPath(root, sourcePath, sandboxPath); err != nil {
		t.Fatalf("copyFileToPath failed: %v", err)
	}

	gotContent, err := os.ReadFile(expectedDest)
	if err != nil {
		t.Fatalf("expected staged file at %q: %v", expectedDest, err)
	}
	if string(gotContent) != wantContent {
		t.Fatalf("unexpected staged content: got %q want %q", string(gotContent), wantContent)
	}

	if _, err := os.Stat(sandboxPath); err == nil {
		t.Fatalf("expected sandbox absolute path %q to remain untouched on host", sandboxPath)
	}
}

func TestWriteSandboxConfigWritesFilesUnderRoot(t *testing.T) {
	root := t.TempDir()
	if err := writeSandboxConfig(root, nil, TrafficModeProxy); err != nil {
		t.Fatalf("writeSandboxConfig failed: %v", err)
	}

	for _, relPath := range []string{
		filepath.Join("etc", "hosts"),
		filepath.Join("etc", "nsswitch.conf"),
		filepath.Join("etc", "resolv.conf"),
	} {
		path := filepath.Join(root, relPath)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected config file at %q: %v", path, err)
		}
	}
}

func TestWriteSandboxConfigWritesDNSLookupConfigInProxyMode(t *testing.T) {
	root := t.TempDir()
	if err := writeSandboxConfig(root, nil, TrafficModeProxy); err != nil {
		t.Fatalf("writeSandboxConfig failed: %v", err)
	}

	nsswitchContent, err := os.ReadFile(filepath.Join(root, "etc", "nsswitch.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if string(nsswitchContent) != "hosts: files dns\n" {
		t.Fatalf("unexpected nsswitch.conf content: got %q", string(nsswitchContent))
	}

	resolvContent, err := os.ReadFile(filepath.Join(root, "etc", "resolv.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resolvContent), "nameserver ") {
		t.Fatalf("expected resolv.conf to contain nameservers, got %q", string(resolvContent))
	}
}

func TestWriteSandboxConfigWritesMITMTrustFilesUnderRoot(t *testing.T) {
	root := t.TempDir()
	caPEM := []byte("test mitm ca\n")

	if err := writeSandboxConfig(root, caPEM, TrafficModeProxy); err != nil {
		t.Fatalf("writeSandboxConfig failed: %v", err)
	}

	for _, relPath := range []string{
		filepath.Join("etc", "ssl", "certs", "ca-certificates.crt"),
		filepath.Join("etc", "pki", "tls", "certs", "ca-bundle.crt"),
		filepath.Join("etc", "ssl", "cert.pem"),
	} {
		path := filepath.Join(root, relPath)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("expected MITM trust file at %q: %v", path, err)
		}
		if string(content) != string(caPEM) {
			t.Fatalf("unexpected trust content at %q: got %q want %q", path, string(content), string(caPEM))
		}
	}
}

func TestWriteSandboxConfigSkipsMITMTrustFilesWhenDisabled(t *testing.T) {
	root := t.TempDir()

	if err := writeSandboxConfig(root, nil, TrafficModeProxy); err != nil {
		t.Fatalf("writeSandboxConfig failed: %v", err)
	}

	for _, relPath := range []string{
		filepath.Join("etc", "ssl", "certs", "ca-certificates.crt"),
		filepath.Join("etc", "pki", "tls", "certs", "ca-bundle.crt"),
		filepath.Join("etc", "ssl", "cert.pem"),
	} {
		path := filepath.Join(root, relPath)
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("did not expect MITM trust file at %q", path)
		}
	}
}

func TestStageSandboxRootWritesMITMTrustFiles(t *testing.T) {
	bboxPath := writeBBoxFixture(t)
	root, err := stageSandboxRoot(SandboxOptions{}, bboxPath, []byte("test mitm ca\n"), TrafficModeProxy)
	if err != nil {
		t.Fatalf("stageSandboxRoot failed: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	path := filepath.Join(root, "etc", "ssl", "certs", "ca-certificates.crt")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected staged MITM trust file at %q: %v", path, err)
	}
	if string(content) != "test mitm ca\n" {
		t.Fatalf("unexpected staged trust content: got %q", string(content))
	}
}

func TestStageSandboxRootCopiesBBoxEntrypoint(t *testing.T) {
	bboxPath := filepath.Join(t.TempDir(), "bbox")
	if err := os.WriteFile(bboxPath, []byte("bbox"), 0o755); err != nil {
		t.Fatal(err)
	}

	root, err := stageSandboxRoot(SandboxOptions{}, bboxPath, nil, TrafficModeProxy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	if _, err := os.Stat(filepath.Join(root, "app", "bbox")); err != nil {
		t.Fatalf("expected /app/bbox: %v", err)
	}
}

func TestStageSandboxRootDoesNotStageSeccompLauncher(t *testing.T) {
	bboxPath := filepath.Join(t.TempDir(), "bbox")
	if err := os.WriteFile(bboxPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write stub bbox: %v", err)
	}

	root, err := stageSandboxRoot(SandboxOptions{}, bboxPath, nil, TrafficModeTransparent)
	if err != nil {
		t.Fatalf("stageSandboxRoot failed: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	stagedLauncher := filepath.Join(root, "app", "bbox-seccomp-launcher")
	if _, err := os.Stat(stagedLauncher); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no staged launcher at %q, got %v", stagedLauncher, err)
	}
}

func TestWriteSandboxConfigWritesTransparentResolvConf(t *testing.T) {
	root := t.TempDir()
	if err := writeSandboxConfig(root, nil, TrafficModeTransparent); err != nil {
		t.Fatalf("writeSandboxConfig failed: %v", err)
	}

	path := filepath.Join(root, "etc", "resolv.conf")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected resolv.conf at %q: %v", path, err)
	}
	if !strings.Contains(string(content), "nameserver ") {
		t.Fatalf("expected staged resolv.conf to contain at least one nameserver line, got %q", string(content))
	}

	nsswitchPath := filepath.Join(root, "etc", "nsswitch.conf")
	nsswitchContent, err := os.ReadFile(nsswitchPath)
	if err != nil {
		t.Fatalf("expected nsswitch.conf at %q: %v", nsswitchPath, err)
	}
	if string(nsswitchContent) != "hosts: files dns\n" {
		t.Fatalf("unexpected nsswitch.conf content: got %q", string(nsswitchContent))
	}
}

func TestWriteSandboxConfigMirrorsHostResolvConfNameservers(t *testing.T) {
	hostNameservers := hostResolvConfNameservers(t)
	if len(hostNameservers) == 0 {
		t.Skip("host resolv.conf has no nameserver entries")
	}

	root := t.TempDir()
	if err := writeSandboxConfig(root, nil, TrafficModeTransparent); err != nil {
		t.Fatalf("writeSandboxConfig failed: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(root, "etc", "resolv.conf"))
	if err != nil {
		t.Fatal(err)
	}
	gotLines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(gotLines) < len(hostNameservers) {
		t.Fatalf("expected at least %d lines in staged resolv.conf, got %d: %q", len(hostNameservers), len(gotLines), string(content))
	}
	for idx, want := range hostNameservers {
		if gotLines[idx] != want {
			t.Fatalf("unexpected nameserver line %d: got %q want %q", idx, gotLines[idx], want)
		}
	}
}

func TestBuildBwrapArgsPassesTransparentTrafficModeFlags(t *testing.T) {
	args := buildBwrapArgs(bwrapArgsConfig{
		root:                  "/tmp/root",
		helperPath:            "/app/bbox",
		proxyListenAddr:       "127.0.0.1:31111",
		bridgeFD:              3,
		trafficMode:           TrafficModeTransparent,
		payloadSeccompBPFPath: "/app/bbox-payload-seccomp.bpf",
	})
	if !containsArgSequence(args, []string{"--traffic-mode", "transparent"}) {
		t.Fatalf("expected args to include --traffic-mode transparent, got %v", args)
	}
	if !containsArgSequence(args, []string{"--payload-seccomp-bpf", "/app/bbox-payload-seccomp.bpf"}) {
		t.Fatalf("expected args to include payload seccomp bpf path, got %v", args)
	}
	if containsArgSequence(args, []string{"--seccomp", "4"}) {
		t.Fatalf("expected transparent helper launch to avoid bwrap-level seccomp, got %v", args)
	}
	wantTail := []string{"/app/bbox", "internal-helper", "--bridge-fd", "3"}
	if !containsArgSequence(args, wantTail) {
		t.Fatalf("expected args to include %v, got %v", wantTail, args)
	}
}

func TestBuildBwrapArgsPassesBridgeAndSeccompFDs(t *testing.T) {
	args := buildBwrapArgs(bwrapArgsConfig{
		root:            "/tmp/root",
		helperPath:      "/app/bbox",
		proxyListenAddr: "127.0.0.1:31111",
		unshareUser:     true,
		bridgeFD:        3,
		seccompFD:       4,
		trafficMode:     TrafficModeProxy,
	})

	if !containsArgSequence(args, []string{"--seccomp", "4"}) {
		t.Fatalf("expected args to include --seccomp 4, got %v", args)
	}
	if !containsArgSequence(args, []string{"--bridge-fd", "3"}) {
		t.Fatalf("expected args to include --bridge-fd 3, got %v", args)
	}
	wantTail := []string{"/app/bbox", "internal-helper", "--bridge-fd", "3"}
	if !containsArgSequence(args, wantTail) {
		t.Fatalf("expected args to include %v, got %v", wantTail, args)
	}
}

func TestBuildBwrapArgsIncludesDockerSocketMount(t *testing.T) {
	args := buildBwrapArgs(bwrapArgsConfig{
		root:            "/tmp/root",
		helperPath:      "/app/bbox",
		proxyListenAddr: "127.0.0.1:31111",
		unshareUser:     true,
		bridgeFD:        3,
		trafficMode:     TrafficModeProxy,
		dockerSocketMount: &dockerSocketMount{
			HostPath:    "/tmp/bbox/docker.sock",
			SandboxPath: "/var/run/docker.sock",
		},
	})
	if !containsArgSequence(args, []string{"--bind", "/tmp/bbox/docker.sock", "/var/run/docker.sock"}) {
		t.Fatalf("expected args to mount docker socket proxy, got %v", args)
	}
}

func TestBuildBwrapArgsMountsStagedBinDirectories(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"bin", "sbin"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	args := buildBwrapArgs(bwrapArgsConfig{
		root:            root,
		helperPath:      "/app/bbox",
		proxyListenAddr: "127.0.0.1:31111",
		unshareUser:     true,
		bridgeFD:        3,
		trafficMode:     TrafficModeProxy,
	})
	if !containsArgSequence(args, []string{"--ro-bind", filepath.Join(root, "bin"), "/bin"}) {
		t.Fatalf("expected args to mount staged /bin, got %v", args)
	}
	if !containsArgSequence(args, []string{"--ro-bind", filepath.Join(root, "sbin"), "/sbin"}) {
		t.Fatalf("expected args to mount staged /sbin, got %v", args)
	}
}

func TestBuildBwrapArgsSkipsUserNamespaceWhenDisabled(t *testing.T) {
	args := buildBwrapArgs(bwrapArgsConfig{
		root:            "/tmp/root",
		helperPath:      "/app/bbox",
		proxyListenAddr: "127.0.0.1:31111",
		unshareUser:     false,
		bridgeFD:        3,
		trafficMode:     TrafficModeProxy,
	})
	if containsString(args, "--unshare-user") {
		t.Fatalf("did not expect --unshare-user in %v", args)
	}
}

func TestBuildBwrapArgsIncludesUserNamespaceWhenEnabled(t *testing.T) {
	args := buildBwrapArgs(bwrapArgsConfig{
		root:            "/tmp/root",
		helperPath:      "/app/bbox",
		proxyListenAddr: "127.0.0.1:31111",
		unshareUser:     true,
		bridgeFD:        3,
		trafficMode:     TrafficModeProxy,
	})
	if !containsString(args, "--unshare-user") {
		t.Fatalf("expected --unshare-user in %v", args)
	}
}

func TestStageSandboxRootStagesNSSDNSWhenAvailable(t *testing.T) {
	libPath, ok := firstExistingPath(nssModuleCandidatePaths("libnss_dns.so.2"))
	if !ok {
		t.Skip("skip: libnss_dns.so.2 not available")
	}

	bboxPath := writeBBoxFixture(t)
	root, err := stageSandboxRoot(SandboxOptions{}, bboxPath, nil, TrafficModeTransparent)
	if err != nil {
		t.Fatalf("stageSandboxRoot failed: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	expected := filepath.Join(root, strings.TrimPrefix(libPath, string(filepath.Separator)))
	if _, err := os.Stat(expected); err != nil {
		t.Fatalf("expected staged libnss_dns at %q: %v", expected, err)
	}

	deps, err := runtimeFilesForBinary(libPath)
	if err != nil {
		t.Fatalf("runtimeFilesForBinary failed: %v", err)
	}
	for _, dep := range deps {
		staged := filepath.Join(root, strings.TrimPrefix(dep, string(filepath.Separator)))
		if _, err := os.Stat(staged); err != nil {
			t.Fatalf("expected staged dependency %q: %v", staged, err)
		}
	}
}

func TestStageSandboxRootStagesNSSDNSInProxyModeWhenAvailable(t *testing.T) {
	libPath, ok := firstExistingPath(nssModuleCandidatePaths("libnss_dns.so.2"))
	if !ok {
		t.Skip("skip: libnss_dns.so.2 not available")
	}

	bboxPath := writeBBoxFixture(t)
	root, err := stageSandboxRoot(SandboxOptions{}, bboxPath, nil, TrafficModeProxy)
	if err != nil {
		t.Fatalf("stageSandboxRoot failed: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	expected := filepath.Join(root, strings.TrimPrefix(libPath, string(filepath.Separator)))
	if _, err := os.Stat(expected); err != nil {
		t.Fatalf("expected staged libnss_dns at %q: %v", expected, err)
	}
}

func TestStageSandboxRootStagesShebangInterpreter(t *testing.T) {
	scriptPath := filepath.Join(t.TempDir(), "script.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	bboxPath := writeBBoxFixture(t)
	root, err := stageSandboxRoot(SandboxOptions{Binaries: []string{scriptPath}}, bboxPath, nil, TrafficModeProxy)
	if err != nil {
		t.Fatalf("stageSandboxRoot failed: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	stagedInterpreter := filepath.Join(root, strings.TrimPrefix("/bin/sh", string(filepath.Separator)))
	if _, err := os.Stat(stagedInterpreter); err != nil {
		t.Fatalf("expected staged shebang interpreter at %q: %v", stagedInterpreter, err)
	}
}

func TestStageSandboxRootStagesEnvShebangTarget(t *testing.T) {
	scriptPath := filepath.Join(t.TempDir(), "script-env.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/usr/bin/env sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	resolvedSh, err := resolveBinary("sh")
	if err != nil {
		t.Fatal(err)
	}

	bboxPath := writeBBoxFixture(t)
	root, err := stageSandboxRoot(SandboxOptions{Binaries: []string{scriptPath}}, bboxPath, nil, TrafficModeProxy)
	if err != nil {
		t.Fatalf("stageSandboxRoot failed: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	for _, path := range []string{"/usr/bin/env", resolvedSh} {
		staged := filepath.Join(root, strings.TrimPrefix(path, string(filepath.Separator)))
		if _, err := os.Stat(staged); err != nil {
			t.Fatalf("expected staged interpreter dependency at %q: %v", staged, err)
		}
	}
}

func TestNSSModuleCandidatePaths(t *testing.T) {
	candidates := nssModuleCandidatePaths("libnss_dns.so.2")
	if !containsString(candidates, "/usr/lib/libnss_dns.so.2") {
		t.Fatalf("expected /usr/lib candidate in %v", candidates)
	}
	if !containsString(candidates, "/lib/libnss_dns.so.2") {
		t.Fatalf("expected /lib candidate in %v", candidates)
	}
	if !containsString(candidates, "/usr/lib64/libnss_dns.so.2") {
		t.Fatalf("expected /usr/lib64 candidate in %v", candidates)
	}
	if !containsString(candidates, "/lib64/libnss_dns.so.2") {
		t.Fatalf("expected /lib64 candidate in %v", candidates)
	}

	for _, dir := range linuxGNUDirs("/usr/lib") {
		expected := filepath.Join(dir, "libnss_dns.so.2")
		if !containsString(candidates, expected) {
			t.Fatalf("expected %s candidate in %v", expected, candidates)
		}
	}
	for _, dir := range linuxGNUDirs("/lib") {
		expected := filepath.Join(dir, "libnss_dns.so.2")
		if !containsString(candidates, expected) {
			t.Fatalf("expected %s candidate in %v", expected, candidates)
		}
	}
}

func containsString(haystack []string, needle string) bool {
	for _, entry := range haystack {
		if entry == needle {
			return true
		}
	}
	return false
}

func linuxGNUDirs(root string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var dirs []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, "-linux-gnu") {
			dirs = append(dirs, filepath.Join(root, name))
		}
	}
	slices.Sort(dirs)
	return dirs
}

func containsArgSequence(haystack []string, needle []string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j, value := range needle {
			if haystack[i+j] != value {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func hostResolvConfNameservers(t *testing.T) []string {
	t.Helper()

	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		t.Fatalf("open host resolv.conf: %v", err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver ") {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan host resolv.conf: %v", err)
	}
	return lines
}

func writeBBoxFixture(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	bboxPath := filepath.Join(dir, "bbox")
	if err := os.WriteFile(bboxPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write bbox fixture %q: %v", bboxPath, err)
	}
	return bboxPath
}
