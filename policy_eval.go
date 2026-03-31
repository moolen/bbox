package bbox

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

type policyEvaluation struct {
	Allowed bool
	Reasons []string
}

func allowedEvaluation() policyEvaluation {
	return policyEvaluation{Allowed: true}
}

func deniedEvaluation(reason string) policyEvaluation {
	return policyEvaluation{Allowed: false, Reasons: []string{reason}}
}

func (e policyEvaluation) firstReasonAsError() error {
	if e.Allowed {
		return nil
	}
	if len(e.Reasons) > 0 {
		return fmt.Errorf("%s", e.Reasons[0])
	}
	return fmt.Errorf("request is denied by policy")
}

func evaluationFromError(err error) policyEvaluation {
	if err != nil {
		return deniedEvaluation(err.Error())
	}
	return allowedEvaluation()
}

func (p compiledPolicy) evaluate(method, hostname string, connect bool) policyEvaluation {
	method = strings.ToUpper(strings.TrimSpace(method))

	if method == "" {
		return deniedEvaluation("request method is required")
	}
	if connect && method != http.MethodConnect {
		return deniedEvaluation("connect requests must use CONNECT method")
	}
	if method == http.MethodConnect && !connect {
		return deniedEvaluation("CONNECT method requires connect request type")
	}

	if !connect && len(p.allowMethods) > 0 {
		if _, ok := p.allowMethods[method]; !ok {
			return deniedEvaluation(fmt.Sprintf("method %s is not allowed", method))
		}
	}

	if connect {
		normalizedHost, port, err := splitConnectTarget(hostname)
		if err != nil {
			return evaluationFromError(err)
		}
		return p.evaluateConnect(normalizedHost, port, false)
	}

	normalizedHost, err := normalizePolicyHostname(hostname)
	if err != nil {
		return evaluationFromError(err)
	}
	return p.evaluateHost(normalizedHost)
}

func (p compiledPolicy) evaluateRequest(req PolicyRequest) policyEvaluation {
	eval := p.evaluate(req.Method, req.Host, false)
	if !eval.Allowed {
		return eval
	}
	if req.BodyTooLarge {
		return deniedEvaluation("request body exceeds inspection limit")
	}

	path := strings.TrimSpace(req.Path)
	if path == "" {
		path = "/"
	}
	eval = evaluationFromError(matchPolicyPatterns("path", path, p.denyPaths, p.allowPaths))
	if !eval.Allowed {
		return eval
	}

	eval = evaluationFromError(p.checkHeaders(req.Header))
	if !eval.Allowed {
		return eval
	}

	return evaluationFromError(matchPolicyPatterns("request body", string(req.Body), p.denyBodies, p.allowBodies))
}

func (p compiledPolicy) evaluateDNS(host string) policyEvaluation {
	normalized := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(host, ".")))
	if normalized == "" {
		return deniedEvaluation("dns hostname is required")
	}

	for _, re := range p.denyHosts {
		if re.MatchString(normalized) {
			return deniedEvaluation(fmt.Sprintf("hostname %s is denied by policy", normalized))
		}
	}
	if len(p.allowHosts) == 0 {
		return allowedEvaluation()
	}
	for _, re := range p.allowHosts {
		if re.MatchString(normalized) {
			return allowedEvaluation()
		}
	}
	return deniedEvaluation(fmt.Sprintf("hostname %s is not allowed by policy", normalized))
}

func (p compiledPolicy) evaluateConnect(host string, port int, transparent bool) policyEvaluation {
	var normalizedHost string
	if transparent {
		normalized, err := normalizePolicyHostname(host)
		if err != nil {
			return evaluationFromError(err)
		}
		normalizedHost = normalized
	} else {
		normalizedHost = strings.ToLower(strings.TrimSpace(host))
		if normalizedHost == "" {
			return deniedEvaluation("CONNECT target host is required")
		}
	}
	if !transparent {
		if !p.allowConnect {
			return deniedEvaluation("CONNECT requests are not allowed")
		}
		if len(p.connectPorts) == 0 {
			return deniedEvaluation("CONNECT port allowlist is empty")
		}
		if !matchConnectPort(p.connectPorts, port) {
			return deniedEvaluation(fmt.Sprintf("CONNECT port %d is not allowed", port))
		}
	}
	return p.evaluateHost(normalizedHost)
}

func (p compiledPolicy) evaluateHost(normalizedHost string) policyEvaluation {
	if ip := net.ParseIP(normalizedHost); ip != nil {
		for _, network := range p.denyIPCIDRs {
			if network.Contains(ip) {
				return deniedEvaluation(fmt.Sprintf("ip literal %s is denied by policy", normalizedHost))
			}
		}
		for _, network := range p.allowIPCIDRs {
			if network.Contains(ip) {
				return allowedEvaluation()
			}
		}
	}

	for _, re := range p.denyHosts {
		if re.MatchString(normalizedHost) {
			return deniedEvaluation(fmt.Sprintf("hostname %s is denied by policy", normalizedHost))
		}
	}

	allowListConfigured := len(p.allowHosts) > 0 || len(p.allowIPCIDRs) > 0
	for _, re := range p.allowHosts {
		if re.MatchString(normalizedHost) {
			return allowedEvaluation()
		}
	}
	if allowListConfigured {
		return deniedEvaluation(fmt.Sprintf("hostname %s is not allowed by policy", normalizedHost))
	}
	return allowedEvaluation()
}
