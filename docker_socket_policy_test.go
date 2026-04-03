package bbox

import (
	"strings"
	"testing"
)

func TestCompileDockerSocketPolicyRejectsUnknownDefaultAction(t *testing.T) {
	_, err := compileDockerSocketPolicy(DockerSocketPolicy{
		DefaultAction: DockerRuleAction("block"),
	})
	if err == nil {
		t.Fatal("expected unknown default action to fail")
	}
}

func TestCompileDockerSocketPolicyRejectsEmptyOperation(t *testing.T) {
	_, err := compileDockerSocketPolicy(DockerSocketPolicy{
		DefaultAction: DockerRuleActionDeny,
		Rules: []DockerSocketRule{
			{
				Action:     DockerRuleActionAllow,
				Operations: []DockerOperation{"   "},
			},
		},
	})
	if err == nil {
		t.Fatal("expected empty operation to fail")
	}
	if !strings.Contains(err.Error(), "operation cannot be empty") {
		t.Fatalf("expected operation error, got %q", err.Error())
	}
}

func TestCompileDockerSocketPolicyRejectsEmptyHTTPMethod(t *testing.T) {
	_, err := compileDockerSocketPolicy(DockerSocketPolicy{
		DefaultAction: DockerRuleActionDeny,
		Rules: []DockerSocketRule{
			{
				Action: DockerRuleActionAllow,
				HTTP: &DockerHTTPMatch{
					Methods: []string{"GET", "  "},
				},
			},
		},
	})
	if err == nil {
		t.Fatal("expected empty HTTP method to fail")
	}
	if !strings.Contains(err.Error(), "HTTP method cannot be empty") {
		t.Fatalf("expected HTTP method error, got %q", err.Error())
	}
}

func TestCompileDockerSocketPolicyRejectsInvalidHTTPPathPattern(t *testing.T) {
	_, err := compileDockerSocketPolicy(DockerSocketPolicy{
		DefaultAction: DockerRuleActionDeny,
		Rules: []DockerSocketRule{
			{
				Action: DockerRuleActionAllow,
				HTTP: &DockerHTTPMatch{
					PathPatterns: []string{"["},
				},
			},
		},
	})
	if err == nil {
		t.Fatal("expected invalid HTTP path regex to fail")
	}
	if !strings.Contains(err.Error(), "HTTP path pattern") {
		t.Fatalf("expected HTTP path pattern context, got %q", err.Error())
	}
}

func TestCompileDockerSocketPolicyNormalizesOperationNames(t *testing.T) {
	compiled, err := compileDockerSocketPolicy(DockerSocketPolicy{
		DefaultAction: DockerRuleActionDeny,
		Rules: []DockerSocketRule{
			{
				Action:     DockerRuleActionAllow,
				Operations: []DockerOperation{" IMAGE_PULL ", "build"},
			},
		},
	})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}

	rule := compiled.rules[0]
	if _, ok := rule.operations[DockerOperation("image_pull")]; !ok {
		t.Fatal("expected image_pull operation to be normalized")
	}
	if _, ok := rule.operations[DockerOperation("build")]; !ok {
		t.Fatal("expected build operation to be normalized")
	}
}

func TestDockerSocketPolicyDefaultDenyWhenNoRuleMatches(t *testing.T) {
	compiled, err := compileDockerSocketPolicy(DockerSocketPolicy{
		Rules: []DockerSocketRule{
			{
				Action:     DockerRuleActionAllow,
				Operations: []DockerOperation{"image_pull"},
			},
		},
	})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}

	got := compiled.evaluate(dockerSocketRequest{
		Method:    "POST",
		Path:      "/build",
		Operation: DockerOperation("build"),
	})
	if got != DockerRuleActionDeny {
		t.Fatalf("expected deny fallback, got %q", got)
	}
}

func TestDockerSocketPolicyFirstMatchingRuleWins(t *testing.T) {
	compiled, err := compileDockerSocketPolicy(DockerSocketPolicy{
		DefaultAction: DockerRuleActionDeny,
		Rules: []DockerSocketRule{
			{
				Action:     DockerRuleActionDeny,
				Operations: []DockerOperation{"image_pull"},
			},
			{
				Action:     DockerRuleActionAllow,
				Operations: []DockerOperation{"image_pull"},
			},
		},
	})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}

	got := compiled.evaluate(dockerSocketRequest{
		Method:    "POST",
		Path:      "/images/create",
		Operation: DockerOperation("image_pull"),
	})
	if got != DockerRuleActionDeny {
		t.Fatalf("expected first matching deny rule to win, got %q", got)
	}
}
