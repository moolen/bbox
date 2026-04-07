package dockerbuild

import (
	"encoding/xml"
	"testing"
)

func TestJavaProxyOptionsFromEnv(t *testing.T) {
	t.Run("parses URL forms and NO_PROXY for java options", func(t *testing.T) {
		got, err := javaProxyOptionsFromEnv([]string{
			"HTTPS_PROXY=http://proxy.internal:8443",
			"NO_PROXY=localhost,.corp.example,127.0.0.1",
		})
		if err != nil {
			t.Fatalf("javaProxyOptionsFromEnv failed: %v", err)
		}

		want := []string{
			"-Dhttps.proxyHost=proxy.internal",
			"-Dhttps.proxyPort=8443",
			"-Dhttp.nonProxyHosts=localhost|*.corp.example|127.0.0.1",
		}
		if len(got) != len(want) {
			t.Fatalf("expected %d proxy flags, got %d: %v", len(want), len(got), got)
		}

		counts := make(map[string]int, len(got))
		for _, flag := range got {
			counts[flag]++
		}
		for _, wantFlag := range want {
			if counts[wantFlag] != 1 {
				t.Fatalf("expected proxy flags %v exactly once each, got %v", want, got)
			}
		}
	})

	t.Run("prefers uppercase and falls back to lowercase with normalized ports", func(t *testing.T) {
		got, err := javaProxyOptionsFromEnv([]string{
			"HTTP_PROXY=proxy.upper.internal",
			"http_proxy=http://proxy.lower.internal:18080",
			"https_proxy=secure.lower.internal:9443",
			"no_proxy=.svc.cluster.local",
		})
		if err != nil {
			t.Fatalf("javaProxyOptionsFromEnv failed: %v", err)
		}

		want := []string{
			"-Dhttp.proxyHost=proxy.upper.internal",
			"-Dhttp.proxyPort=80",
			"-Dhttps.proxyHost=secure.lower.internal",
			"-Dhttps.proxyPort=9443",
			"-Dhttp.nonProxyHosts=*.svc.cluster.local",
		}
		if len(got) != len(want) {
			t.Fatalf("expected %d proxy flags, got %d: %v", len(want), len(got), got)
		}

		counts := make(map[string]int, len(got))
		for _, flag := range got {
			counts[flag]++
		}
		for _, wantFlag := range want {
			if counts[wantFlag] != 1 {
				t.Fatalf("expected proxy flags %v exactly once each, got %v", want, got)
			}
		}
	})
}

func TestJavaNonProxyHosts(t *testing.T) {
	got := javaNonProxyHosts([]string{
		"localhost",
		".corp.example",
		"*.svc.internal",
		"127.0.0.1",
		"10.0.0.0/8",
		"api.example:8443",
		"[::1]",
		"localhost",
		" ",
	})

	const want = "localhost|*.corp.example|*.svc.internal|127.0.0.1"
	if got != want {
		t.Fatalf("expected java non-proxy hosts %q, got %q", want, got)
	}
}

func TestRenderMavenSettings(t *testing.T) {
	cfg := proxyConfig{
		HTTPHost:      "proxy-http.internal",
		HTTPPort:      "8080",
		HTTPSHost:     "proxy-https.internal",
		HTTPSPort:     "8443",
		NonProxyHosts: []string{"localhost", ".corp.example", "10.0.0.0/8"},
	}

	raw, err := renderMavenSettings(cfg)
	if err != nil {
		t.Fatalf("renderMavenSettings failed: %v", err)
	}

	type parsedProxy struct {
		ID            string `xml:"id"`
		Active        bool   `xml:"active"`
		Protocol      string `xml:"protocol"`
		Host          string `xml:"host"`
		Port          string `xml:"port"`
		NonProxyHosts string `xml:"nonProxyHosts"`
	}
	type parsedSettings struct {
		XMLName xml.Name      `xml:"settings"`
		Proxies []parsedProxy `xml:"proxies>proxy"`
	}

	var doc parsedSettings
	if err := xml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal rendered settings: %v", err)
	}
	if doc.XMLName.Local != "settings" {
		t.Fatalf("expected root element settings, got %q", doc.XMLName.Local)
	}
	if len(doc.Proxies) != 2 {
		t.Fatalf("expected 2 Maven proxy entries, got %d: %q", len(doc.Proxies), string(raw))
	}

	byProtocol := map[string]parsedProxy{}
	for _, p := range doc.Proxies {
		byProtocol[p.Protocol] = p
	}

	httpProxy, ok := byProtocol["http"]
	if !ok {
		t.Fatalf("expected HTTP proxy in %q", string(raw))
	}
	if !httpProxy.Active || httpProxy.Host != "proxy-http.internal" || httpProxy.Port != "8080" {
		t.Fatalf("unexpected HTTP proxy entry: %#v", httpProxy)
	}
	if httpProxy.NonProxyHosts != "localhost|*.corp.example" {
		t.Fatalf("expected translated HTTP nonProxyHosts, got %q", httpProxy.NonProxyHosts)
	}

	httpsProxy, ok := byProtocol["https"]
	if !ok {
		t.Fatalf("expected HTTPS proxy in %q", string(raw))
	}
	if !httpsProxy.Active || httpsProxy.Host != "proxy-https.internal" || httpsProxy.Port != "8443" {
		t.Fatalf("unexpected HTTPS proxy entry: %#v", httpsProxy)
	}
	if httpsProxy.NonProxyHosts != "localhost|*.corp.example" {
		t.Fatalf("expected translated HTTPS nonProxyHosts, got %q", httpsProxy.NonProxyHosts)
	}
}
