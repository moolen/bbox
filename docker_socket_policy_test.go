package bbox

import "testing"

func TestCompileDockerSocketPolicyRejectsUnknownDefaultAction(t *testing.T) {
	_, err := compileDockerSocketPolicy(DockerSocketPolicy{
		DefaultAction: DockerRuleAction("block"),
	})
	if err == nil {
		t.Fatal("expected unknown default action to fail")
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
	if _, ok := rule.operations[dockerOperation("image_pull")]; !ok {
		t.Fatal("expected image_pull operation to be normalized")
	}
	if _, ok := rule.operations[dockerOperation("build")]; !ok {
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
		Operation: dockerOperation("build"),
	})
	if got != dockerRuleActionDeny {
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
		Operation: dockerOperation("image_pull"),
	})
	if got != dockerRuleActionDeny {
		t.Fatalf("expected first matching deny rule to win, got %q", got)
	}
}
