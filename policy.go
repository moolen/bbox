package bbox

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

type compiledPolicy struct {
	allowMethods map[string]struct{}
	allowHosts   []*regexp.Regexp
	denyHosts    []*regexp.Regexp
	allowConnect bool
	connectPorts []portRange
}

type portRange struct {
	start int
	end   int
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
	method = strings.ToUpper(strings.TrimSpace(method))

	if method == "" {
		return fmt.Errorf("request method is required")
	}
	if connect && method != http.MethodConnect {
		return fmt.Errorf("connect requests must use CONNECT method")
	}
	if method == http.MethodConnect && !connect {
		return fmt.Errorf("CONNECT method requires connect request type")
	}

	if !connect && len(p.allowMethods) > 0 {
		if _, ok := p.allowMethods[method]; !ok {
			return fmt.Errorf("method %s is not allowed", method)
		}
	}
	var (
		normalizedHost string
		err            error
	)
	if connect {
		var port int
		normalizedHost, port, err = splitConnectTarget(hostname)
		if err != nil {
			return err
		}
		if !p.allowConnect {
			return fmt.Errorf("CONNECT requests are not allowed")
		}
		if len(p.connectPorts) == 0 {
			return fmt.Errorf("CONNECT port allowlist is empty")
		}
		if !matchConnectPort(p.connectPorts, port) {
			return fmt.Errorf("CONNECT port %d is not allowed", port)
		}
	} else {
		normalizedHost, err = normalizePolicyHostname(hostname)
		if err != nil {
			return err
		}
	}

	for _, re := range p.denyHosts {
		if re.MatchString(normalizedHost) {
			return fmt.Errorf("hostname %s is denied by policy", normalizedHost)
		}
	}

	allowListConfigured := len(p.allowHosts) > 0
	for _, re := range p.allowHosts {
		if re.MatchString(normalizedHost) {
			return nil
		}
	}
	if allowListConfigured {
		return fmt.Errorf("hostname %s is not allowed by policy", normalizedHost)
	}
	return nil
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
