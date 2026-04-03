package bbox

import (
	"strings"
	"testing"
)

func TestNewProxyManagerFailsFastOnInvalidDockerSocketPolicy(t *testing.T) {
	_, err := NewProxyManager(ProxyOptions{
		DockerSocket: DockerSocketOptions{
			Policy: DockerSocketPolicy{
				DefaultAction: DockerRuleActionDeny,
				Rules: []DockerSocketRule{
					{
						Action: DockerRuleActionAllow,
						HTTP: &DockerHTTPMatch{
							PathPatterns: []string{"["},
						},
					},
				},
			},
		},
	})
	if err == nil {
		t.Fatal("expected invalid docker socket policy to fail manager construction")
	}
	if !strings.Contains(err.Error(), "HTTP path pattern") {
		t.Fatalf("expected docker policy compile error context, got %q", err.Error())
	}
}
