package bbox

import "strings"

type dockerOperation string

type dockerRuleAction string

const (
	dockerRuleActionAllow dockerRuleAction = "allow"
	dockerRuleActionDeny  dockerRuleAction = "deny"
)

type dockerSocketRequest struct {
	Method    string
	Path      string
	Operation dockerOperation
}

func normalizeDockerOperation(op string) dockerOperation {
	return dockerOperation(strings.ToLower(strings.TrimSpace(op)))
}
