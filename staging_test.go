package bbox

import (
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
	} {
		path := filepath.Join(root, relPath)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected config file at %q: %v", path, err)
		}
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
	root, err := stageSandboxRoot(SandboxOptions{}, "/bin/sh", []byte("test mitm ca\n"), TrafficModeProxy)
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
	want := "nameserver 127.0.0.1\noptions ndots:1\n"
	if string(content) != want {
		t.Fatalf("unexpected resolv.conf content: got %q want %q", string(content), want)
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

func TestBuildBwrapArgsPassesTransparentTrafficModeFlags(t *testing.T) {
	args := buildBwrapArgs("/tmp/root", "/app/bbox-helper", "127.0.0.1:31111", MITMOptions{}, nil, TrafficModeTransparent)
	if !containsArgSequence(args, []string{"--traffic-mode", "transparent"}) {
		t.Fatalf("expected args to include --traffic-mode transparent, got %v", args)
	}
}

func TestStageSandboxRootStagesNSSDNSWhenAvailable(t *testing.T) {
	libPath, ok := firstExistingPath(nssModuleCandidatePaths("libnss_dns.so.2"))
	if !ok {
		t.Skip("skip: libnss_dns.so.2 not available")
	}

	root, err := stageSandboxRoot(SandboxOptions{}, "/bin/sh", nil, TrafficModeTransparent)
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
