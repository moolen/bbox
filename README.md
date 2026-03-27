# bbox

`bbox` is a Linux-focused Go library for running processes inside unprivileged `bubblewrap` sandboxes with:

- isolated filesystem, PID, and network namespaces
- one shared host-side proxy manager
- one sandbox-local HTTP proxy listener per sandbox helper
- per-sandbox regex-based egress policy
- automatic staging of requested binaries and their shared-library dependencies
- explicit read-only and read-write bind mounts

Phase 1 is intentionally narrow. It supports plain HTTP proxying, CONNECT tunneling, and persistent sandboxes. CONNECT is tunnel-only, not TLS MITM, so the host can enforce destination and method policy but does not decrypt HTTPS payloads. It does not yet implement TLS MITM, WebSocket-aware proxying, or full HTTP/2 interception.

## Requirements

- Linux
- `bwrap` on the host `PATH`
- a Go toolchain on the host `PATH`
- any payload binaries you want to stage, for example `curl`, `wget`, or `go`

## Demo

Run the built-in demo with the default two sandboxes:

```bash
go run ./cmd/demo
```

Default behavior:

- `alpha` allows `^example[.]com$`
- `beta` allows `^github[.]com$`
- both sandboxes fetch `http://example.com` through the same host proxy manager

You can also define the sandboxes explicitly:

```bash
go run ./cmd/demo \
  --sandbox 'alpha=^example[.]com$' \
  --sandbox 'beta=^github[.]com$' \
  --bin curl \
  --target-url http://example.com
```

## Library Example

```go
package main

import (
	"context"
	"log"

	"github.com/moolen/bbox"
)

func main() {
	ctx := context.Background()

	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{})
	if err != nil {
		log.Fatal(err)
	}
	defer manager.Close()

	sandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "demo",
		Binaries: []string{"curl"},
		Mounts: []bbox.Mount{
			{Source: "/tmp", Target: "/workspace", ReadOnly: false},
		},
		Policy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^example[.]com$`},
			AllowHTTPMethods:  []string{"GET"},
			AllowConnect:      true,
			AllowConnectPorts: []string{"443"},
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

	log.Printf("exit=%d stdout=%q stderr=%q", result.ExitCode, result.Stdout, result.Stderr)
}
```

## Notes

- Each sandbox runs a long-lived helper process inside `bwrap`.
- `ProxyOptions.ListenAddr` sets the sandbox-local proxy listen address used by each helper. Leave it empty to use `127.0.0.1:31111`, or set it to `127.0.0.1:0` to let the kernel choose a free port. The sandbox runtime env is updated from the helper's reported bound address.
- Payload processes do not inherit the host bridge file descriptor.
- Per-sandbox policy is enforced on the host before outbound requests are made.
- Use `NetworkPolicy.AllowConnect` and `NetworkPolicy.AllowConnectPorts` to allow CONNECT tunnels to specific destination ports.
