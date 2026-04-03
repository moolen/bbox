package bbox

import (
	"fmt"
	"regexp"
	"strings"
)

type compiledDockerSocketPolicy struct {
	defaultAction dockerRuleAction
	rules         []compiledDockerSocketRule
}

type compiledDockerSocketRule struct {
	action       dockerRuleAction
	operations   map[dockerOperation]struct{}
	httpMethods  map[string]struct{}
	pathPatterns []*regexp.Regexp
}

func compileDockerSocketPolicy(policy DockerSocketPolicy) (*compiledDockerSocketPolicy, error) {
	defaultAction, err := normalizeDockerRuleAction(policy.DefaultAction, true)
	if err != nil {
		return nil, err
	}

	compiled := &compiledDockerSocketPolicy{
		defaultAction: defaultAction,
		rules:         make([]compiledDockerSocketRule, 0, len(policy.Rules)),
	}
	for idx, rule := range policy.Rules {
		compiledRule, err := compileDockerSocketRule(idx, rule)
		if err != nil {
			return nil, err
		}
		compiled.rules = append(compiled.rules, compiledRule)
	}
	return compiled, nil
}

func compileDockerSocketRule(index int, rule DockerSocketRule) (compiledDockerSocketRule, error) {
	action, err := normalizeDockerRuleAction(rule.Action, false)
	if err != nil {
		return compiledDockerSocketRule{}, fmt.Errorf("rule %d action: %w", index, err)
	}

	compiled := compiledDockerSocketRule{
		action:      action,
		operations:  map[dockerOperation]struct{}{},
		httpMethods: map[string]struct{}{},
	}

	for _, op := range rule.Operations {
		normalized := normalizeDockerOperation(string(op))
		if normalized == "" {
			return compiledDockerSocketRule{}, fmt.Errorf("rule %d operation cannot be empty", index)
		}
		compiled.operations[normalized] = struct{}{}
	}

	if rule.HTTP == nil {
		return compiled, nil
	}

	for _, method := range rule.HTTP.Methods {
		normalized := strings.ToUpper(strings.TrimSpace(method))
		if normalized == "" {
			return compiledDockerSocketRule{}, fmt.Errorf("rule %d HTTP method cannot be empty", index)
		}
		compiled.httpMethods[normalized] = struct{}{}
	}

	for _, pattern := range rule.HTTP.PathPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return compiledDockerSocketRule{}, fmt.Errorf("compile rule %d HTTP path pattern %q: %w", index, pattern, err)
		}
		compiled.pathPatterns = append(compiled.pathPatterns, re)
	}

	return compiled, nil
}

func normalizeDockerRuleAction(action DockerRuleAction, allowDefault bool) (dockerRuleAction, error) {
	normalized := dockerRuleAction(strings.ToLower(strings.TrimSpace(string(action))))
	if normalized == "" && allowDefault {
		return dockerRuleActionDeny, nil
	}
	switch normalized {
	case dockerRuleActionAllow, dockerRuleActionDeny:
		return normalized, nil
	default:
		return "", fmt.Errorf("invalid docker rule action %q", action)
	}
}

func (p *compiledDockerSocketPolicy) evaluate(req dockerSocketRequest) dockerRuleAction {
	if p == nil {
		return dockerRuleActionDeny
	}

	for _, rule := range p.rules {
		if !rule.matches(req) {
			continue
		}
		return rule.action
	}

	if p.defaultAction == "" {
		return dockerRuleActionDeny
	}
	return p.defaultAction
}

func (r compiledDockerSocketRule) matches(req dockerSocketRequest) bool {
	if len(r.operations) > 0 {
		if _, ok := r.operations[normalizeDockerOperation(string(req.Operation))]; !ok {
			return false
		}
	}

	if len(r.httpMethods) > 0 {
		method := strings.ToUpper(strings.TrimSpace(req.Method))
		if _, ok := r.httpMethods[method]; !ok {
			return false
		}
	}

	if len(r.pathPatterns) > 0 {
		path := strings.TrimSpace(req.Path)
		if path == "" {
			path = "/"
		}
		for _, pattern := range r.pathPatterns {
			if pattern.MatchString(path) {
				return true
			}
		}
		return false
	}

	return true
}
