package bbox

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

type compiledPolicy struct {
	allowMethods map[string]struct{}
	allowHosts   []*regexp.Regexp
	denyHosts    []*regexp.Regexp
	allowConnect bool
}

func compilePolicy(policy NetworkPolicy) (*compiledPolicy, error) {
	compiled := &compiledPolicy{
		allowMethods: make(map[string]struct{}),
		allowConnect: policy.AllowConnect,
	}

	for _, method := range policy.AllowHTTPMethods {
		normalized := strings.ToUpper(strings.TrimSpace(method))
		if normalized == "" {
			return nil, fmt.Errorf("allow HTTP method cannot be empty")
		}
		compiled.allowMethods[normalized] = struct{}{}
	}

	for _, pattern := range policy.AllowHostPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compile allow host pattern %q: %w", pattern, err)
		}
		compiled.allowHosts = append(compiled.allowHosts, re)
	}

	for _, pattern := range policy.DenyHostPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compile deny host pattern %q: %w", pattern, err)
		}
		compiled.denyHosts = append(compiled.denyHosts, re)
	}

	return compiled, nil
}

func (p compiledPolicy) Check(method, hostname string, connect bool) error {
	method = strings.ToUpper(strings.TrimSpace(method))
	hostname = strings.ToLower(strings.TrimSpace(hostname))

	if method == "" {
		return fmt.Errorf("request method is required")
	}
	if hostname == "" {
		return fmt.Errorf("request hostname is required")
	}
	if connect && method != http.MethodConnect {
		return fmt.Errorf("connect requests must use CONNECT method")
	}
	if method == http.MethodConnect && !connect {
		return fmt.Errorf("CONNECT method requires connect request type")
	}

	if connect && !p.allowConnect {
		return fmt.Errorf("CONNECT requests are not allowed")
	}
	if len(p.allowMethods) > 0 {
		if _, ok := p.allowMethods[method]; !ok {
			return fmt.Errorf("method %s is not allowed", method)
		}
	}

	for _, re := range p.denyHosts {
		if re.MatchString(hostname) {
			return fmt.Errorf("hostname %s is denied by policy", hostname)
		}
	}

	allowListConfigured := len(p.allowHosts) > 0
	for _, re := range p.allowHosts {
		if re.MatchString(hostname) {
			return nil
		}
	}
	if allowListConfigured {
		return fmt.Errorf("hostname %s is not allowed by policy", hostname)
	}
	return nil
}
