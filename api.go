package bbox

import (
	"fmt"
	"regexp"
)

type compiledPolicy struct {
	allowHostRegex []*regexp.Regexp
	denyHostRegex  []*regexp.Regexp
}

func NewProxyManager(opts ProxyOptions) (*ProxyManager, error) {
	if len(opts.NetworkPolicy.AllowHTTPMethods) > 0 {
		return nil, fmt.Errorf("unsupported NetworkPolicy.AllowHTTPMethods in Task 1")
	}
	if opts.NetworkPolicy.AllowConnect {
		return nil, fmt.Errorf("unsupported NetworkPolicy.AllowConnect=true in Task 1")
	}

	policy, err := compilePolicy(opts.NetworkPolicy)
	if err != nil {
		return nil, err
	}
	return &ProxyManager{policy: policy}, nil
}

func compilePolicy(policy NetworkPolicy) (*compiledPolicy, error) {
	compiled := &compiledPolicy{}

	for _, pattern := range policy.AllowHostPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compile allow host pattern %q: %w", pattern, err)
		}
		compiled.allowHostRegex = append(compiled.allowHostRegex, re)
	}

	for _, pattern := range policy.DenyHostPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compile deny host pattern %q: %w", pattern, err)
		}
		compiled.denyHostRegex = append(compiled.denyHostRegex, re)
	}

	return compiled, nil
}
