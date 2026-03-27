package bbox

import "testing"

func TestNewProxyManagerRejectsInvalidRegex(t *testing.T) {
	_, err := NewProxyManager(ProxyOptions{
		NetworkPolicy: NetworkPolicy{
			AllowHostPatterns: []string{"["},
		},
	})
	if err == nil {
		t.Fatal("expected constructor to reject invalid policy regex")
	}
}
