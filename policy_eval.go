package bbox

import (
	"fmt"
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

	var firstReason string
	for _, rule := range p.rules {
		if rule.hasConnectPorts() || rule.hasPathPatterns() || rule.hasHeaderPatterns() || rule.hasBodyPatterns() {
			continue
		}
		if !rule.matchesMethod(method) {
			if firstReason == "" {
				firstReason = fmt.Sprintf("method %s is not allowed by policy", method)
			}
			continue
		}
		if matched, reason := rule.matchesHostDetailed(normalizedHost); !matched {
			if firstReason == "" {
				firstReason = reason
			}
			continue
		}
		return allowedEvaluation()
	}

	if firstReason != "" {
		return deniedEvaluation(firstReason)
	}
	return deniedEvaluation("no policy rule matched request")
}

func (p compiledPolicy) evaluateRequest(req PolicyRequest) policyEvaluation {
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		return deniedEvaluation("request method is required")
	}

	normalizedHost, err := normalizePolicyHostname(req.Host)
	if err != nil {
		return evaluationFromError(err)
	}

	path := strings.TrimSpace(req.Path)
	if path == "" {
		path = "/"
	}

	bodyTooLarge := false
	var firstReason string
	for _, rule := range p.rules {
		if rule.hasConnectPorts() {
			continue
		}
		if !rule.matchesMethod(method) {
			if firstReason == "" {
				firstReason = fmt.Sprintf("method %s is not allowed by policy", method)
			}
			continue
		}
		if matched, reason := rule.matchesHostDetailed(normalizedHost); !matched {
			if firstReason == "" {
				firstReason = reason
			}
			continue
		}
		if !rule.matchesPath(path) {
			if firstReason == "" {
				firstReason = fmt.Sprintf("path %q is not allowed by policy", path)
			}
			continue
		}
		if matched, reason := rule.matchesHeadersDetailed(req.Header); !matched {
			if firstReason == "" {
				firstReason = reason
			}
			continue
		}
		if req.BodyTooLarge && rule.hasBodyPatterns() {
			bodyTooLarge = true
			continue
		}
		if matched, reason := rule.matchesBodyDetailed(req.Body); !matched {
			if firstReason == "" {
				firstReason = reason
			}
			continue
		}
		return allowedEvaluation()
	}

	if bodyTooLarge {
		return deniedEvaluation("request body exceeds inspection limit")
	}
	if firstReason != "" {
		return deniedEvaluation(firstReason)
	}
	return deniedEvaluation("no policy rule matched request")
}

func (p compiledPolicy) evaluateDNS(host string) policyEvaluation {
	normalized := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(host, ".")))
	if normalized == "" {
		return deniedEvaluation("dns hostname is required")
	}

	var firstReason string
	for _, rule := range p.rules {
		if rule.hasIPCIDRs() || rule.hasHTTPMethods() || rule.hasConnectPorts() || rule.hasPathPatterns() || rule.hasHeaderPatterns() || rule.hasBodyPatterns() {
			continue
		}
		if matched, reason := rule.matchesHostDetailed(normalized); !matched {
			if firstReason == "" {
				firstReason = reason
			}
			continue
		}
		return allowedEvaluation()
	}

	if firstReason != "" {
		return deniedEvaluation(firstReason)
	}
	return deniedEvaluation("no policy rule matched dns hostname")
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

	var firstReason string
	for _, rule := range p.rules {
		if rule.hasHTTPMethods() || rule.hasPathPatterns() || rule.hasHeaderPatterns() || rule.hasBodyPatterns() {
			continue
		}
		if transparent && rule.hasConnectPorts() {
			continue
		}
		if matched, reason := rule.matchesHostDetailed(normalizedHost); !matched {
			if firstReason == "" {
				firstReason = reason
			}
			continue
		}
		if !transparent {
			if len(rule.connectPorts) == 0 || !matchConnectPort(rule.connectPorts, port) {
				if firstReason == "" {
					firstReason = fmt.Sprintf("CONNECT port %d is not allowed", port)
				}
				continue
			}
		}
		return allowedEvaluation()
	}

	if firstReason != "" {
		return deniedEvaluation(firstReason)
	}
	if transparent {
		return deniedEvaluation("no policy rule matched connect target")
	}
	return deniedEvaluation("no policy rule matched CONNECT target")
}
