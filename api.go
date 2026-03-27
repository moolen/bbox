package bbox

import "regexp"

type compiledPolicy struct {
	allowHostRegex []*regexp.Regexp
	denyHostRegex  []*regexp.Regexp
}

func NewProxyManager(opts ProxyOptions) (*ProxyManager, error) {
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
			return nil, err
		}
		compiled.allowHostRegex = append(compiled.allowHostRegex, re)
	}

	for _, pattern := range policy.DenyHostPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		compiled.denyHostRegex = append(compiled.denyHostRegex, re)
	}

	return compiled, nil
}
