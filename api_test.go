package bbox

import "testing"

func TestNewProxyManagerRejectsInvalidRegex(t *testing.T) {
	_, err := NewProxyManager(ProxyOptions{})
	if err != nil {
		t.Fatalf("unexpected manager construction error: %v", err)
	}

	_, err = compilePolicy(NetworkPolicy{
		AllowHostPatterns: []string{"["},
	})
	if err == nil {
		t.Fatal("expected invalid regex compilation to fail")
	}
}
