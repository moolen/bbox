package bbox

import (
	"fmt"
	"net"
	"net/http"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
)

type compiledPolicy struct {
	allowMethods map[string]struct{}
	allowHosts   []*regexp.Regexp
	denyHosts    []*regexp.Regexp
	allowIPCIDRs []*net.IPNet
	denyIPCIDRs  []*net.IPNet
	allowConnect bool
	connectPorts []portRange
	allowPaths   []*regexp.Regexp
	denyPaths    []*regexp.Regexp
	allowHeaders map[string][]*regexp.Regexp
	denyHeaders  map[string][]*regexp.Regexp
	allowBodies  []*regexp.Regexp
	denyBodies   []*regexp.Regexp
}

type portRange struct {
	start int
	end   int
}

type PolicyRequest struct {
	Method       string
	Host         string
	Path         string
	Header       http.Header
	Body         []byte
	BodyTooLarge bool
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
	for _, cidr := range policy.AllowIPCIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("parse allow IP CIDR %q: %w", cidr, err)
		}
		compiled.allowIPCIDRs = append(compiled.allowIPCIDRs, network)
	}
	for _, cidr := range policy.DenyIPCIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("parse deny IP CIDR %q: %w", cidr, err)
		}
		compiled.denyIPCIDRs = append(compiled.denyIPCIDRs, network)
	}
	for _, pattern := range policy.AllowPathPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compile allow path pattern %q: %w", pattern, err)
		}
		compiled.allowPaths = append(compiled.allowPaths, re)
	}
	for _, pattern := range policy.DenyPathPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compile deny path pattern %q: %w", pattern, err)
		}
		compiled.denyPaths = append(compiled.denyPaths, re)
	}
	allowHeaders, err := compileHeaderPatterns("allow", policy.AllowHeaderPatterns)
	if err != nil {
		return nil, err
	}
	compiled.allowHeaders = allowHeaders
	denyHeaders, err := compileHeaderPatterns("deny", policy.DenyHeaderPatterns)
	if err != nil {
		return nil, err
	}
	compiled.denyHeaders = denyHeaders
	for _, pattern := range policy.AllowBodyPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compile allow body pattern %q: %w", pattern, err)
		}
		compiled.allowBodies = append(compiled.allowBodies, re)
	}
	for _, pattern := range policy.DenyBodyPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compile deny body pattern %q: %w", pattern, err)
		}
		compiled.denyBodies = append(compiled.denyBodies, re)
	}
	for _, spec := range policy.AllowConnectPorts {
		parsed, err := parseConnectPortSpec(spec)
		if err != nil {
			return nil, fmt.Errorf("parse connect port spec %q: %w", spec, err)
		}
		compiled.connectPorts = append(compiled.connectPorts, parsed)
	}

	return compiled, nil
}

func (p compiledPolicy) Check(method, hostname string, connect bool) error {
	return p.evaluate(method, hostname, connect).firstReasonAsError()
}

func (p compiledPolicy) CheckRequest(req PolicyRequest) error {
	return p.evaluateRequest(req).firstReasonAsError()
}

func (p compiledPolicy) CheckDNS(host string) error {
	return p.evaluateDNS(host).firstReasonAsError()
}

func (p compiledPolicy) CheckTransparentConnect(host string) error {
	return p.evaluateConnect(host, 0, true).firstReasonAsError()
}

func normalizePolicyHostname(hostname string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(hostname))
	if normalized == "" {
		return "", fmt.Errorf("request hostname is required")
	}

	if !strings.Contains(normalized, ":") {
		return normalized, nil
	}

	if strings.HasPrefix(normalized, "[") {
		if strings.HasSuffix(normalized, "]") {
			inner := strings.TrimSpace(strings.TrimPrefix(strings.TrimSuffix(normalized, "]"), "["))
			if inner == "" {
				return "", fmt.Errorf("request hostname is required")
			}
			if !isIPv6Literal(inner) {
				return "", fmt.Errorf("invalid host %q", hostname)
			}
			return inner, nil
		}

		host, _, err := splitHostPortStrict(normalized)
		if err != nil {
			return "", fmt.Errorf("invalid host:port %q", hostname)
		}
		host = strings.TrimSpace(strings.ToLower(host))
		if !isIPv6Literal(host) {
			return "", fmt.Errorf("invalid host %q", hostname)
		}
		return host, nil
	}

	if strings.Count(normalized, ":") == 1 {
		host, _, err := splitHostPortStrict(normalized)
		if err != nil {
			return "", fmt.Errorf("invalid host:port %q", hostname)
		}
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			return "", fmt.Errorf("request hostname is required")
		}
		return host, nil
	}

	return "", fmt.Errorf("invalid host %q", hostname)
}

func splitHostPortStrict(hostport string) (string, string, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", "", err
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 0 || portNum > 65535 {
		return "", "", fmt.Errorf("invalid port %q", port)
	}
	return host, port, nil
}

func parseConnectPortSpec(spec string) (portRange, error) {
	normalized := strings.TrimSpace(spec)
	if normalized == "" {
		return portRange{}, fmt.Errorf("port spec cannot be empty")
	}

	if strings.Contains(normalized, "-") {
		parts := strings.Split(normalized, "-")
		if len(parts) != 2 {
			return portRange{}, fmt.Errorf("invalid port range %q", spec)
		}
		start, err := parsePortNumber(parts[0])
		if err != nil {
			return portRange{}, err
		}
		end, err := parsePortNumber(parts[1])
		if err != nil {
			return portRange{}, err
		}
		if start > end {
			return portRange{}, fmt.Errorf("invalid descending port range %q", spec)
		}
		return portRange{start: start, end: end}, nil
	}

	port, err := parsePortNumber(normalized)
	if err != nil {
		return portRange{}, err
	}
	return portRange{start: port, end: port}, nil
}

func matchConnectPort(ranges []portRange, port int) bool {
	for _, allowed := range ranges {
		if port >= allowed.start && port <= allowed.end {
			return true
		}
	}
	return false
}

func splitConnectTarget(hostport string) (string, int, error) {
	host, portText, err := splitHostPortStrict(strings.TrimSpace(hostport))
	if err != nil {
		return "", 0, fmt.Errorf("CONNECT target must be host:port")
	}
	normalizedHost := strings.ToLower(strings.TrimSpace(host))
	if normalizedHost == "" {
		return "", 0, fmt.Errorf("CONNECT target host is required")
	}
	if strings.Contains(normalizedHost, ":") && !isIPv6Literal(normalizedHost) {
		return "", 0, fmt.Errorf("invalid CONNECT target host %q", host)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return "", 0, fmt.Errorf("invalid CONNECT target port %q", portText)
	}
	if port == 0 {
		return "", 0, fmt.Errorf("invalid CONNECT target port %q", portText)
	}
	return normalizedHost, port, nil
}

func parsePortNumber(value string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("invalid port %q", value)
	}
	return port, nil
}

func isIPv6Literal(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && strings.Contains(host, ":")
}

func compileHeaderPatterns(label string, patterns map[string][]string) (map[string][]*regexp.Regexp, error) {
	if len(patterns) == 0 {
		return nil, nil
	}

	compiled := make(map[string][]*regexp.Regexp, len(patterns))
	for headerName, values := range patterns {
		normalizedName := strings.ToLower(strings.TrimSpace(headerName))
		if normalizedName == "" {
			return nil, fmt.Errorf("%s header pattern name cannot be empty", label)
		}
		for _, pattern := range values {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("compile %s header pattern %q for %q: %w", label, pattern, headerName, err)
			}
			compiled[normalizedName] = append(compiled[normalizedName], re)
		}
	}
	return compiled, nil
}

func matchPolicyPatterns(label, value string, deny, allow []*regexp.Regexp) error {
	for _, re := range deny {
		if re.MatchString(value) {
			return fmt.Errorf("%s %q is denied by policy", label, value)
		}
	}
	if len(allow) == 0 {
		return nil
	}
	for _, re := range allow {
		if re.MatchString(value) {
			return nil
		}
	}
	return fmt.Errorf("%s %q is not allowed by policy", label, value)
}

func (p compiledPolicy) checkHeaders(headers http.Header) error {
	normalized := make(map[string][]string, len(headers))
	for headerName, values := range headers {
		normalized[strings.ToLower(textproto.CanonicalMIMEHeaderKey(headerName))] = values
	}

	for headerName, rules := range p.denyHeaders {
		for _, value := range normalized[headerName] {
			for _, re := range rules {
				if re.MatchString(value) {
					return fmt.Errorf("header %s is denied by policy", headerName)
				}
			}
		}
	}

	for headerName, rules := range p.allowHeaders {
		matched := false
		for _, value := range normalized[headerName] {
			for _, re := range rules {
				if re.MatchString(value) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return fmt.Errorf("header %s is not allowed by policy", headerName)
		}
	}

	return nil
}
