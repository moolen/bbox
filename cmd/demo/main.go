package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/moolen/bbox"
)

type stringListFlag []string

func (f *stringListFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *stringListFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

type sandboxConfig struct {
	name          string
	allowHostExpr string
}

type sandboxHandle struct {
	name string
	sb   *bbox.Sandbox
}

func main() {
	var (
		targetURL string
		binaries  stringListFlag
		sandboxes stringListFlag
	)

	flag.StringVar(&targetURL, "target-url", "http://example.com", "URL that each sandbox should fetch through the shared proxy")
	flag.Var(&binaries, "bin", "binary to stage into each sandbox (repeatable)")
	flag.Var(&sandboxes, "sandbox", "sandbox spec in the form name=allow-host-regex (repeatable)")
	flag.Parse()

	if len(binaries) == 0 {
		binaries = append(binaries, "curl")
	}

	curlPath, err := exec.LookPath("curl")
	if err != nil {
		log.Fatalf("resolve curl: %v", err)
	}
	if !containsString(binaries, "curl") && !containsString(binaries, curlPath) {
		binaries = append(binaries, curlPath)
	}

	configs, err := parseSandboxConfigs(sandboxes)
	if err != nil {
		log.Fatal(err)
	}
	if len(configs) == 0 {
		configs = []sandboxConfig{
			{name: "alpha", allowHostExpr: `^example[.]com$`},
			{name: "beta", allowHostExpr: `^github[.]com$`},
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{})
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			log.Printf("close manager: %v", err)
		}
	}()

	var sandboxesToClose []sandboxHandle
	defer func() {
		for _, sandbox := range sandboxesToClose {
			if err := sandbox.sb.Close(); err != nil {
				log.Printf("close sandbox %q: %v", sandbox.name, err)
			}
		}
	}()

	for _, cfg := range configs {
		sb, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
			Name:     cfg.name,
			Binaries: append([]string(nil), binaries...),
			Policy: bbox.NetworkPolicy{
				AllowHostPatterns: []string{cfg.allowHostExpr},
				AllowHTTPMethods:  []string{"GET"},
			},
		})
		if err != nil {
			log.Fatalf("create sandbox %q: %v", cfg.name, err)
		}
		sandboxesToClose = append(sandboxesToClose, sandboxHandle{name: cfg.name, sb: sb})
	}

	fmt.Printf("target: %s\n", targetURL)
	for i, sandbox := range sandboxesToClose {
		cfg := configs[i]
		fmt.Printf("\n[%s] allow-host=%s\n", cfg.name, cfg.allowHostExpr)

		result, err := sandbox.sb.Run(ctx, []string{curlPath, "-sS", "-o", "-", "-w", "\n%{http_code}\n", targetURL}, bbox.RunOptions{})
		if err != nil {
			fmt.Printf("run error: %v\n", err)
			continue
		}

		fmt.Printf("exit=%d\n", result.ExitCode)
		stdout := strings.TrimSpace(string(result.Stdout))
		stderr := strings.TrimSpace(string(result.Stderr))
		if stdout != "" {
			fmt.Printf("stdout:\n%s\n", stdout)
		}
		if stderr != "" {
			fmt.Printf("stderr:\n%s\n", stderr)
		}
	}
}

func parseSandboxConfigs(values []string) ([]sandboxConfig, error) {
	configs := make([]sandboxConfig, 0, len(values))
	for _, raw := range values {
		name, regex, ok := strings.Cut(raw, "=")
		name = strings.TrimSpace(name)
		regex = strings.TrimSpace(regex)
		if !ok || name == "" || regex == "" {
			return nil, fmt.Errorf("invalid sandbox spec %q, want name=allow-host-regex", raw)
		}
		configs = append(configs, sandboxConfig{name: name, allowHostExpr: regex})
	}
	return configs, nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
