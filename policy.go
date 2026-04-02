package bbox

import (
	"fmt"
	"net"
	"net/http"
	"net/textproto"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type compiledPolicy struct {
	rules []compiledPolicyRule
}

type compiledPolicyRule struct {
	hostPatterns   []*regexp.Regexp
	ipCIDRs        []*net.IPNet
	httpMethods    map[string]struct{}
	connectPorts   []portRange
	pathPatterns   []*regexp.Regexp
	headerPatterns map[string][]*regexp.Regexp
	bodyPatterns   []*regexp.Regexp
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
		rules: make([]compiledPolicyRule, 0, len(policy.Rules)),
	}

	for idx, rule := range policy.Rules {
		compiledRule, err := compilePolicyRule(idx, rule)
		if err != nil {
			return nil, err
		}
		compiled.rules = append(compiled.rules, compiledRule)
	}

	return compiled, nil
}

func compilePolicyRule(index int, rule PolicyRule) (compiledPolicyRule, error) {
	compiled := compiledPolicyRule{
		httpMethods: make(map[string]struct{}),
	}

	for _, method := range rule.HTTPMethods {
		normalized := strings.ToUpper(strings.TrimSpace(method))
		if normalized == "" {
			return compiledPolicyRule{}, fmt.Errorf("rule %d HTTP method cannot be empty", index)
		}
		compiled.httpMethods[normalized] = struct{}{}
	}

	hostPatterns, err := compileRegexps(rule.HostPatterns, func(pattern string, compileErr error) error {
		return fmt.Errorf("compile rule %d host pattern %q: %w", index, pattern, compileErr)
	})
	if err != nil {
		return compiledPolicyRule{}, err
	}
	compiled.hostPatterns = hostPatterns

	for _, cidr := range rule.IPCIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return compiledPolicyRule{}, fmt.Errorf("parse rule %d IP CIDR %q: %w", index, cidr, err)
		}
		compiled.ipCIDRs = append(compiled.ipCIDRs, network)
	}

	for _, spec := range rule.ConnectPorts {
		parsed, err := parseConnectPortSpec(spec)
		if err != nil {
			return compiledPolicyRule{}, fmt.Errorf("parse rule %d connect port spec %q: %w", index, spec, err)
		}
		compiled.connectPorts = append(compiled.connectPorts, parsed)
	}

	pathPatterns, err := compileRegexps(rule.PathPatterns, func(pattern string, compileErr error) error {
		return fmt.Errorf("compile rule %d path pattern %q: %w", index, pattern, compileErr)
	})
	if err != nil {
		return compiledPolicyRule{}, err
	}
	compiled.pathPatterns = pathPatterns

	headerPatterns, err := compileHeaderPatterns(index, rule.HeaderPatterns)
	if err != nil {
		return compiledPolicyRule{}, err
	}
	compiled.headerPatterns = headerPatterns

	bodyPatterns, err := compileRegexps(rule.BodyPatterns, func(pattern string, compileErr error) error {
		return fmt.Errorf("compile rule %d body pattern %q: %w", index, pattern, compileErr)
	})
	if err != nil {
		return compiledPolicyRule{}, err
	}
	compiled.bodyPatterns = bodyPatterns

	return compiled, nil
}

func compileRegexps(patterns []string, wrap func(string, error) error) ([]*regexp.Regexp, error) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, wrap(pattern, err)
		}
		compiled = append(compiled, re)
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

func compileHeaderPatterns(ruleIndex int, patterns map[string][]string) (map[string][]*regexp.Regexp, error) {
	if len(patterns) == 0 {
		return nil, nil
	}

	compiled := make(map[string][]*regexp.Regexp, len(patterns))
	for headerName, values := range patterns {
		normalizedName := strings.ToLower(strings.TrimSpace(textproto.CanonicalMIMEHeaderKey(headerName)))
		if normalizedName == "" {
			return nil, fmt.Errorf("rule %d header pattern name cannot be empty", ruleIndex)
		}
		for _, pattern := range values {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("compile rule %d header pattern %q for %q: %w", ruleIndex, pattern, headerName, err)
			}
			compiled[normalizedName] = append(compiled[normalizedName], re)
		}
	}
	return compiled, nil
}

func (r compiledPolicyRule) hasHTTPMethods() bool {
	return len(r.httpMethods) > 0
}

func (r compiledPolicyRule) hasConnectPorts() bool {
	return len(r.connectPorts) > 0
}

func (r compiledPolicyRule) hasPathPatterns() bool {
	return len(r.pathPatterns) > 0
}

func (r compiledPolicyRule) hasHeaderPatterns() bool {
	return len(r.headerPatterns) > 0
}

func (r compiledPolicyRule) hasBodyPatterns() bool {
	return len(r.bodyPatterns) > 0
}

func (r compiledPolicyRule) hasIPCIDRs() bool {
	return len(r.ipCIDRs) > 0
}

func (r compiledPolicyRule) matchesHost(normalizedHost string) bool {
	matched, _ := r.matchesHostDetailed(normalizedHost)
	return matched
}

func (r compiledPolicyRule) matchesHostDetailed(normalizedHost string) (bool, string) {
	hostMatched := len(r.hostPatterns) == 0
	if len(r.hostPatterns) > 0 {
		for _, re := range r.hostPatterns {
			if re.MatchString(normalizedHost) {
				hostMatched = true
				break
			}
		}
	}
	if !hostMatched {
		return false, hostnameDeniedReason(normalizedHost)
	}

	if len(r.ipCIDRs) == 0 {
		return true, ""
	}
	ip := net.ParseIP(normalizedHost)
	if ip == nil {
		return false, hostnameDeniedReason(normalizedHost)
	}
	for _, network := range r.ipCIDRs {
		if network.Contains(ip) {
			return true, ""
		}
	}
	return false, fmt.Sprintf("ip literal %s is not allowed by policy", normalizedHost)
}

func (r compiledPolicyRule) matchesMethod(method string) bool {
	if len(r.httpMethods) == 0 {
		return true
	}
	_, ok := r.httpMethods[method]
	return ok
}

func (r compiledPolicyRule) matchesPath(path string) bool {
	if len(r.pathPatterns) == 0 {
		return true
	}
	for _, re := range r.pathPatterns {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

func (r compiledPolicyRule) matchesHeaders(headers http.Header) bool {
	matched, _ := r.matchesHeadersDetailed(headers)
	return matched
}

func (r compiledPolicyRule) matchesHeadersDetailed(headers http.Header) (bool, string) {
	if len(r.headerPatterns) == 0 {
		return true, ""
	}

	normalized := make(map[string][]string, len(headers))
	for headerName, values := range headers {
		normalized[strings.ToLower(textproto.CanonicalMIMEHeaderKey(headerName))] = values
	}

	headerNames := make([]string, 0, len(r.headerPatterns))
	for headerName := range r.headerPatterns {
		headerNames = append(headerNames, headerName)
	}
	sort.Strings(headerNames)
	for _, headerName := range headerNames {
		rules := r.headerPatterns[headerName]
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
			return false, fmt.Sprintf("header %s is not allowed by policy", headerName)
		}
	}

	return true, ""
}

func (r compiledPolicyRule) matchesBody(body []byte) bool {
	matched, _ := r.matchesBodyDetailed(body)
	return matched
}

func (r compiledPolicyRule) matchesBodyDetailed(body []byte) (bool, string) {
	if len(r.bodyPatterns) == 0 {
		return true, ""
	}
	bodyText := string(body)
	for _, re := range r.bodyPatterns {
		if re.MatchString(bodyText) {
			return true, ""
		}
	}
	return false, "request body is not allowed by policy"
}

func hostnameDeniedReason(normalizedHost string) string {
	return fmt.Sprintf("hostname %s is not allowed by policy", normalizedHost)
}
