package dockerbuild

import (
	"encoding/xml"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type proxyConfig struct {
	HTTPHost      string
	HTTPPort      string
	HTTPSHost     string
	HTTPSPort     string
	NonProxyHosts []string
}

func (cfg proxyConfig) Enabled() bool {
	return (cfg.HTTPHost != "" && cfg.HTTPPort != "") || (cfg.HTTPSHost != "" && cfg.HTTPSPort != "")
}

func proxyConfigFromEnv(env []string) (proxyConfig, error) {
	cfg := proxyConfig{}

	httpRaw, ok := preferredProxyEnvValue(env, "HTTP_PROXY", "http_proxy")
	if ok {
		host, port, err := parseProxyURL(httpRaw, "http")
		if err != nil {
			return proxyConfig{}, fmt.Errorf("parse HTTP proxy: %w", err)
		}
		cfg.HTTPHost = host
		cfg.HTTPPort = port
	}

	httpsRaw, ok := preferredProxyEnvValue(env, "HTTPS_PROXY", "https_proxy")
	if ok {
		host, port, err := parseProxyURL(httpsRaw, "https")
		if err != nil {
			return proxyConfig{}, fmt.Errorf("parse HTTPS proxy: %w", err)
		}
		cfg.HTTPSHost = host
		cfg.HTTPSPort = port
	}

	if nonProxyRaw, ok := preferredProxyEnvValue(env, "NO_PROXY", "no_proxy"); ok {
		cfg.NonProxyHosts = splitNonProxyHosts(nonProxyRaw)
	}

	return cfg, nil
}

func javaProxyOptionsFromEnv(env []string) ([]string, error) {
	cfg, err := proxyConfigFromEnv(env)
	if err != nil {
		return nil, err
	}
	return javaProxyOptions(cfg), nil
}

func javaProxyOptions(cfg proxyConfig) []string {
	opts := make([]string, 0, 5)
	if cfg.HTTPHost != "" && cfg.HTTPPort != "" {
		opts = append(opts,
			"-Dhttp.proxyHost="+cfg.HTTPHost,
			"-Dhttp.proxyPort="+cfg.HTTPPort,
		)
	}
	if cfg.HTTPSHost != "" && cfg.HTTPSPort != "" {
		opts = append(opts,
			"-Dhttps.proxyHost="+cfg.HTTPSHost,
			"-Dhttps.proxyPort="+cfg.HTTPSPort,
		)
	}
	if nonProxy := javaNonProxyHosts(cfg.NonProxyHosts); nonProxy != "" {
		opts = append(opts, "-Dhttp.nonProxyHosts="+nonProxy)
	}
	return opts
}

func javaNonProxyHosts(nonProxy []string) string {
	normalized := make([]string, 0, len(nonProxy))
	seen := make(map[string]struct{}, len(nonProxy))

	for _, entry := range nonProxy {
		parsed, ok := normalizeJavaNonProxyEntry(entry)
		if !ok {
			continue
		}
		if _, already := seen[parsed]; already {
			continue
		}
		seen[parsed] = struct{}{}
		normalized = append(normalized, parsed)
	}

	return strings.Join(normalized, "|")
}

func renderMavenSettings(cfg proxyConfig) ([]byte, error) {
	type proxy struct {
		ID            string `xml:"id"`
		Active        bool   `xml:"active"`
		Protocol      string `xml:"protocol"`
		Host          string `xml:"host"`
		Port          string `xml:"port"`
		NonProxyHosts string `xml:"nonProxyHosts,omitempty"`
	}
	type settings struct {
		XMLName xml.Name `xml:"settings"`
		Proxies []proxy  `xml:"proxies>proxy"`
	}

	if !cfg.Enabled() {
		return nil, fmt.Errorf("proxy config is empty")
	}

	nonProxy := javaNonProxyHosts(cfg.NonProxyHosts)
	proxies := make([]proxy, 0, 2)
	if cfg.HTTPHost != "" && cfg.HTTPPort != "" {
		proxies = append(proxies, proxy{
			ID:            "bbox-http-proxy",
			Active:        true,
			Protocol:      "http",
			Host:          cfg.HTTPHost,
			Port:          cfg.HTTPPort,
			NonProxyHosts: nonProxy,
		})
	}
	if cfg.HTTPSHost != "" && cfg.HTTPSPort != "" {
		proxies = append(proxies, proxy{
			ID:            "bbox-https-proxy",
			Active:        true,
			Protocol:      "https",
			Host:          cfg.HTTPSHost,
			Port:          cfg.HTTPSPort,
			NonProxyHosts: nonProxy,
		})
	}

	doc := settings{Proxies: proxies}
	return xml.MarshalIndent(doc, "", "  ")
}

func preferredProxyEnvValue(env []string, uppercase string, lowercase string) (string, bool) {
	if value, ok := lookupEnvValue(env, uppercase); ok {
		value = strings.TrimSpace(value)
		if value == "" {
			return "", false
		}
		return value, true
	}
	if value, ok := lookupEnvValue(env, lowercase); ok {
		value = strings.TrimSpace(value)
		if value == "" {
			return "", false
		}
		return value, true
	}
	return "", false
}

func parseProxyURL(raw string, defaultScheme string) (string, string, error) {
	parsedValue := strings.TrimSpace(raw)
	if parsedValue == "" {
		return "", "", fmt.Errorf("proxy value is empty")
	}

	if !strings.Contains(parsedValue, "://") {
		parsedValue = defaultScheme + "://" + parsedValue
	}

	u, err := url.Parse(parsedValue)
	if err != nil {
		return "", "", fmt.Errorf("invalid proxy URL: %w", err)
	}

	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme == "" {
		scheme = defaultScheme
	}
	if scheme != "http" && scheme != "https" {
		return "", "", fmt.Errorf("unsupported proxy scheme %q", scheme)
	}

	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return "", "", fmt.Errorf("proxy host is empty")
	}

	port := strings.TrimSpace(u.Port())
	if port == "" {
		port = defaultPortForProxyScheme(scheme)
	}
	normalizedPort, err := normalizeProxyPort(port)
	if err != nil {
		return "", "", err
	}

	return host, normalizedPort, nil
}

func defaultPortForProxyScheme(scheme string) string {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "https":
		return "443"
	default:
		return "80"
	}
}

func normalizeProxyPort(raw string) (string, error) {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("proxy port %q is not numeric", raw)
	}
	if port <= 0 || port > 65535 {
		return "", fmt.Errorf("proxy port %d is out of range", port)
	}
	return strconv.Itoa(port), nil
}

func splitNonProxyHosts(raw string) []string {
	parts := strings.Split(raw, ",")
	hosts := make([]string, 0, len(parts))
	for _, part := range parts {
		host := strings.TrimSpace(part)
		if host == "" {
			continue
		}
		hosts = append(hosts, host)
	}
	return hosts
}

func normalizeJavaNonProxyEntry(raw string) (string, bool) {
	entry := strings.TrimSpace(raw)
	if entry == "" {
		return "", false
	}

	if entry == "*" {
		return entry, true
	}

	if strings.ContainsAny(entry, "[]/| \t\r\n") {
		return "", false
	}

	if strings.HasPrefix(entry, ".") {
		suffix := strings.TrimPrefix(entry, ".")
		if !isValidJavaNonProxyHost(suffix) {
			return "", false
		}
		return "*." + suffix, true
	}

	if strings.HasPrefix(entry, "*.") {
		suffix := strings.TrimPrefix(entry, "*.")
		if !isValidJavaNonProxyHost(suffix) {
			return "", false
		}
		return "*." + suffix, true
	}

	if strings.Contains(entry, "*") || strings.Contains(entry, ":") {
		return "", false
	}
	if !isValidJavaNonProxyHost(entry) {
		return "", false
	}
	return entry, true
}

func isValidJavaNonProxyHost(host string) bool {
	if host == "" || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	if strings.Contains(host, "..") {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '.' || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}
