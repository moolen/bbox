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
	if err := writeSandboxConfig(root); err != nil {
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
