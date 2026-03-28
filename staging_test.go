package bbox

import (
	"os"
	"path/filepath"
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
	if os.Geteuid() == 0 {
		t.Skip("skip as root to avoid touching host /etc in regression case")
	}

	root := t.TempDir()
	if err := writeSandboxConfig(root, nil); err != nil {
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

	if err := writeSandboxConfig(root, caPEM); err != nil {
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

	if err := writeSandboxConfig(root, nil); err != nil {
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
	root, err := stageSandboxRoot(SandboxOptions{}, "/bin/sh", []byte("test mitm ca\n"))
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
