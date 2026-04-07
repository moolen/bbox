package dockerbuild

import (
	"slices"
	"testing"
)

func TestJavaProxyOptionsFromEnv(t *testing.T) {
	got, err := javaProxyOptionsFromEnv([]string{
		"HTTPS_PROXY=http://proxy.internal:8443",
		"NO_PROXY=localhost,.corp.example,127.0.0.1",
	})
	if err != nil {
		t.Fatalf("javaProxyOptionsFromEnv failed: %v", err)
	}
	for _, want := range []string{
		"-Dhttps.proxyHost=proxy.internal",
		"-Dhttps.proxyPort=8443",
		"-Dhttp.nonProxyHosts=localhost|*.corp.example|127.0.0.1",
	} {
		if !slices.Contains(got, want) {
			t.Fatalf("missing %q in %v", want, got)
		}
	}
}
