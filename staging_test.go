package bbox

import "testing"

func TestParseLddOutputFindsAbsolutePaths(t *testing.T) {
	input := "\tlibcurl.so.4 => /usr/lib/libcurl.so.4 (0x0)\n\t/lib64/ld-linux-x86-64.so.2 (0x0)\n"
	got := parseLddOutput(input)
	if len(got) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(got))
	}
}
