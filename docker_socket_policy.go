package bbox

import (
	"fmt"
	"regexp"
	"strings"
)

type compiledDockerSocketPolicy struct {
	defaultAction DockerRuleAction
	rules         []compiledDockerSocketRule
}

type compiledDockerSocketRule struct {
	action       DockerRuleAction
	operations   map[DockerOperation]struct{}
	httpMethods  map[string]struct{}
	pathPatterns []*regexp.Regexp
	build        *compiledDockerBuildMatch
}

type compiledDockerBuildMatch struct {
	context            DockerBuildContextMatch
	dockerfilePatterns []*regexp.Regexp
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
		operations:  map[DockerOperation]struct{}{},
		httpMethods: map[string]struct{}{},
	}

	for _, op := range rule.Operations {
		normalized := normalizeDockerOperation(string(op))
		if normalized == "" {
			return compiledDockerSocketRule{}, fmt.Errorf("rule %d operation cannot be empty", index)
		}
		compiled.operations[normalized] = struct{}{}
	}

	if rule.HTTP != nil {
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
	}

	if rule.Build != nil {
		build, err := compileDockerBuildMatch(index, *rule.Build)
		if err != nil {
			return compiledDockerSocketRule{}, err
		}
		compiled.build = build
	}

	return compiled, nil
}

func compileDockerBuildMatch(index int, match DockerBuildMatch) (*compiledDockerBuildMatch, error) {
	context, err := normalizeDockerBuildContextMatch(match.Context)
	if err != nil {
		return nil, fmt.Errorf("rule %d build context: %w", index, err)
	}

	compiled := &compiledDockerBuildMatch{
		context:            context,
		dockerfilePatterns: make([]*regexp.Regexp, 0, len(match.DockerfilePaths)),
	}
	for _, pattern := range match.DockerfilePaths {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compile rule %d build dockerfile path pattern %q: %w", index, pattern, err)
		}
		compiled.dockerfilePatterns = append(compiled.dockerfilePatterns, re)
	}

	return compiled, nil
}

func normalizeDockerRuleAction(action DockerRuleAction, allowDefault bool) (DockerRuleAction, error) {
	normalized := DockerRuleAction(strings.ToLower(strings.TrimSpace(string(action))))
	if normalized == "" && allowDefault {
		return DockerRuleActionDeny, nil
	}
	switch normalized {
	case DockerRuleActionAllow, DockerRuleActionDeny:
		return normalized, nil
	default:
		return "", fmt.Errorf("invalid docker rule action %q", action)
	}
}

func normalizeDockerBuildContextMatch(value DockerBuildContextMatch) (DockerBuildContextMatch, error) {
	normalized := DockerBuildContextMatch(strings.ToLower(strings.TrimSpace(string(value))))
	switch normalized {
	case "", DockerBuildContextMatchLocalOnly:
		return normalized, nil
	default:
		return "", fmt.Errorf("invalid docker build context match %q", value)
	}
}

func (p *compiledDockerSocketPolicy) evaluate(req dockerSocketRequest) DockerRuleAction {
	if p == nil {
		return DockerRuleActionDeny
	}

	for _, rule := range p.rules {
		if !rule.matches(req) {
			continue
		}
		return rule.action
	}

	if p.defaultAction == "" {
		return DockerRuleActionDeny
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

	if r.build != nil && !r.build.matches(req.Build) {
		return false
	}

	return true
}

func (m *compiledDockerBuildMatch) matches(req *dockerBuildRequest) bool {
	if m == nil {
		return true
	}
	if req == nil {
		return false
	}
	if m.context == DockerBuildContextMatchLocalOnly {
		if req.Remote != "" {
			return false
		}
		if req.BodyKind != "tar" {
			return false
		}
	}
	if len(m.dockerfilePatterns) == 0 {
		return true
	}
	for _, pattern := range m.dockerfilePatterns {
		if pattern.MatchString(req.Dockerfile) {
			return true
		}
	}
	return false
}
