package bbox_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/moolen/bbox"
)

type recordingAccessLogger struct {
	mu      sync.Mutex
	entries []bbox.AccessLogEntry
}

type ProxyModeSandbox struct{}

type SeccompSandbox struct{}

type TransparentModeSandbox struct{}

func (r *recordingAccessLogger) LogAccess(entry bbox.AccessLogEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, entry)
}

func (r *recordingAccessLogger) snapshot() []bbox.AccessLogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	entries := make([]bbox.AccessLogEntry, len(r.entries))
	copy(entries, r.entries)
	return entries
}

func ExampleNewProxyManager() {
	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{
		ListenAddr: "127.0.0.1:0",
		NetworkPolicy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^example[.]com$`},
			AllowHTTPMethods:  []string{"GET"},
			AllowConnect:      true,
			AllowConnectPorts: []string{"443"},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer manager.Close()

	fmt.Println("manager ready")
	// Output: manager ready
}

func ExampleProxyOptions() {
	opts := bbox.ProxyOptions{
		ListenAddr: "127.0.0.1:0",
		MITM: bbox.MITMOptions{
			Enabled:             true,
			MaxRequestBodyBytes: 64 << 10,
		},
		NetworkPolicy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^api[.]github[.]com$`, `^github[.]com$`},
			AllowHTTPMethods:  []string{"GET"},
			AllowConnect:      true,
			AllowConnectPorts: []string{"443"},
			AllowPathPatterns: []string{`^/repos/`},
		},
	}

	fmt.Println(opts.ListenAddr)
	fmt.Println(opts.MITM.Enabled)
	fmt.Println(opts.NetworkPolicy.AllowConnect)
	// Output:
	// 127.0.0.1:0
	// true
	// true
}

func ExampleProxyManager_NewSandbox() {
	// This is a real end-to-end setup example. It is kept dormant during normal
	// go test runs because it depends on Linux, bubblewrap, staged binaries, and
	// outbound network access.
	if os.Getenv("BBOX_RUN_EXAMPLES") == "" {
		return
	}

	ctx := context.Background()
	logger := &recordingAccessLogger{}

	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{
		ListenAddr:   "127.0.0.1:0",
		AccessLogger: logger,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer manager.Close()

	sandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "docs-example",
		Binaries: []string{"curl"},
		Mounts: []bbox.Mount{
			{Source: "/tmp", Target: "/workspace"},
		},
		Policy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^example[.]com$`},
			AllowHTTPMethods:  []string{"GET"},
		},
		WorkDir: "/workspace",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer sandbox.Close()

	result, err := sandbox.Run(ctx, []string{
		"curl",
		"-sS",
		"http://example.com",
	}, bbox.RunOptions{})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("proxy=%s exit=%d stdout=%dB stderr=%dB", sandbox.ProxyURL(), result.ExitCode, len(result.Stdout), len(result.Stderr))
	log.Printf("accessed=%d entries=%d", len(sandbox.AccessedDomains()), len(logger.snapshot()))
}

func ExampleProxyModeSandbox() {
	opts := bbox.SandboxOptions{
		TrafficMode: bbox.TrafficModeProxy,
		Policy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^example[.]com$`},
			AllowHTTPMethods:  []string{"GET"},
			AllowConnect:      true,
			AllowConnectPorts: []string{"443"},
		},
	}

	fmt.Println(opts.TrafficMode)
	// Output: proxy
}

func ExampleSeccompSandbox() {
	opts := bbox.SandboxOptions{
		Seccomp: bbox.SeccompOptions{
			Profile: bbox.SeccompProfileRestricted,
			Rules: []bbox.SeccompRule{
				bbox.DenySyscall("socketpair"),
			},
		},
	}

	fmt.Println(opts.Seccomp.Profile)
	fmt.Println(opts.Seccomp.Rules[0].Syscall)
	// Output:
	// restricted
	// socketpair
}

func ExampleTransparentModeSandbox() {
	managerOpts := bbox.ProxyOptions{
		MITM: bbox.MITMOptions{
			Enabled:             true,
			MaxRequestBodyBytes: 64 << 10,
		},
	}
	sandboxOpts := bbox.SandboxOptions{
		TrafficMode: bbox.TrafficModeTransparent,
		Policy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^api[.]github[.]com$`},
			AllowHTTPMethods:  []string{"GET"},
			AllowPathPatterns: []string{`^/repos/`},
		},
	}

	fmt.Println(managerOpts.MITM.Enabled)
	fmt.Println(sandboxOpts.TrafficMode)
	// Output:
	// true
	// transparent
}
