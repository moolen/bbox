package dockerbuild

import "testing"

func TestJavaProxyOptionsFromEnv(t *testing.T) {
	got, err := javaProxyOptionsFromEnv([]string{
		"HTTPS_PROXY=http://proxy.internal:8443",
		"NO_PROXY=localhost,.corp.example,127.0.0.1",
	})
	if err != nil {
		t.Fatalf("javaProxyOptionsFromEnv failed: %v", err)
	}

	want := []string{
		"-Dhttps.proxyHost=proxy.internal",
		"-Dhttps.proxyPort=8443",
		"-Dhttp.nonProxyHosts=localhost|*.corp.example|127.0.0.1",
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d proxy flags, got %d: %v", len(want), len(got), got)
	}

	counts := make(map[string]int, len(got))
	for _, flag := range got {
		counts[flag]++
	}
	for _, wantFlag := range want {
		if counts[wantFlag] != 1 {
			t.Fatalf("expected proxy flags %v exactly once each, got %v", want, got)
		}
	}
}
