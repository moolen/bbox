# bbox

`bbox` is a Linux-focused Go library for running processes inside unprivileged `bubblewrap` sandboxes with:

- isolated filesystem, PID, and network namespaces
- built-in seccomp hardening with baseline and restricted profiles
- one shared host-side proxy manager
- one sandbox-local traffic ingress per sandbox helper
- per-sandbox regex-based egress policy
- optional manager-wide TLS MITM with ephemeral CA trust injection
- decrypted HTTPS request policy for paths, headers, and bounded request bodies
- HTTP/2 interception support for concurrent client streams
- automatic staging of requested binaries and their shared-library dependencies
- explicit read-only and read-write bind mounts

`bbox` supports both explicit proxy mode and transparent mode. Proxy mode injects `HTTP_PROXY` / `HTTPS_PROXY` into sandboxed runs. Transparent mode uses sandbox-local DNS plus loopback listeners on `:80` and `:443`, while still reusing the same host-side policy engine. Response-body inspection, WebSocket-specific interception behavior, and persistent CA lifecycle management are still out of scope.

## Requirements

- Linux
- `bwrap` on the host `PATH`
- `libseccomp` headers and runtime available to the Go toolchain
- a Go toolchain on the host `PATH`
- any payload binaries you want to stage, for example `curl`, `wget`, or `go`

## Docker

This repository includes an agent-oriented container image with:

- Go and the standard build toolchain
- `bbox` and `bbox-helper` on `PATH`
- `bubblewrap`, `libseccomp`, `golangci-lint`, `govulncheck`
- common shell/debugging tools such as `git`, `rg`, `jq`, `curl`, `wget`, `strace`, and `python3`

Local helper targets:

```bash
make build
make docker-build IMAGE=bbox-agent TAG=dev
make lint
```

The image is meant to be used with a bind-mounted checkout at `/workspace`, because `bbox` rebuilds `cmd/bbox-helper` from the module root when it starts a sandbox.

Start an interactive agent shell:

```bash
docker run --rm -it \
  -v "$PWD":/workspace \
  -w /workspace \
  bbox-agent:dev
```

Inside the container you can run:

```bash
make build
make lint
go test ./...
```

To actually launch nested `bwrap` sandboxes from inside Docker, a plain container is not enough on this host. A verified, known-good invocation is `--privileged`:

```bash
docker run --rm -it \
  --privileged \
  -v "$PWD":/workspace \
  -w /workspace \
  bbox-agent:dev
```

Proxy-mode example inside that container:

```bash
bbox \
  --allowed-domain example.com \
  -- /usr/bin/curl -fsS http://example.com
```

Transparent mode binds `127.0.0.1:53`, `127.0.0.1:80`, and `127.0.0.1:443` inside the nested sandbox namespace, and it requires `--mitm`. The verified Docker setup above uses `--privileged`, which already covers the low-port bind requirement; adding `--cap-add=NET_BIND_SERVICE` on top is redundant.

Transparent-mode example inside that container:

```bash
bbox \
  --traffic-mode transparent \
  --mitm \
  --allowed-domain example.com \
  -- /usr/bin/curl -fsS http://example.com
```

## Seccomp Hardening

Every sandbox enables seccomp by default with the `baseline` profile. The baseline profile is designed for an unprivileged `bwrap` sandbox: it keeps `--new-session`, blocks `TIOCSTI` ioctl injection as defense in depth, denies namespace and mount reconfiguration syscalls, blocks process-inspection syscalls that could target the long-lived helper, and blocks uncommon privileged kernel attack surfaces such as `bpf`, module loading, and keyring syscalls.

The `restricted` profile keeps those baseline protections and additionally blocks in-sandbox seccomp installation via `seccomp(2)` and `prctl(PR_SET_SECCOMP)`. That is stricter, but it can break applications such as browsers that expect to install their own seccomp filters after startup.

The zero value is secure-by-default:

```go
opts := bbox.SandboxOptions{
	Name:     "default-seccomp",
	Binaries: []string{"curl"},
}
```

Pick the stricter preset explicitly when you want it:

```go
opts := bbox.SandboxOptions{
	Name:     "restricted-seccomp",
	Binaries: []string{"curl"},
	Seccomp: bbox.SeccompOptions{
		Profile: bbox.SeccompProfileRestricted,
	},
}
```

Callers can also add targeted rules on top of either built-in profile:

```go
opts := bbox.SandboxOptions{
	Name:     "custom-seccomp",
	Binaries: []string{"curl"},
	Seccomp: bbox.SeccompOptions{
		Rules: []bbox.SeccompRule{
			bbox.DenySyscall("socketpair"),
		},
	},
}
```

Use `SeccompProfileCustom` when you want only your own rule set, or set `Seccomp.Disabled=true` to turn seccomp off entirely.

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

## TLS MITM

Enable MITM once on the shared manager:

```go
manager, err := bbox.NewProxyManager(bbox.ProxyOptions{
	MaxRequestBodyBytes: 64 << 10,
	MITM:                bbox.MITMOptions{Enabled: true},
	NetworkPolicy: bbox.NetworkPolicy{
		AllowHostPatterns: []string{`^api[.]github[.]com$`},
		AllowHTTPMethods:  []string{"GET", "POST"},
		AllowConnect:      true,
		AllowConnectPorts: []string{"443"},
		AllowPathPatterns: []string{`^/repos/`},
	},
})
```

When MITM is enabled, `bbox` generates one ephemeral CA per `ProxyManager`, injects that CA into each staged sandbox root, evaluates decrypted HTTPS requests on the host before dialing upstream, and rejects requests whose decrypted `Host` disagrees with the real upstream authority.

Buffered request and response bodies are capped by default. `ProxyOptions.MaxRequestBodyBytes` defaults to `1 << 20` and `ProxyOptions.MaxResponseBodyBytes` defaults to `4 << 20`. Oversized requests are denied and oversized upstream responses fail deterministically instead of being buffered without bound.

## Traffic Modes

Choose the traffic mode per sandbox with `SandboxOptions.TrafficMode`.

Proxy mode is the default:

```go
sandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
	Name:        "proxy-demo",
	TrafficMode: bbox.TrafficModeProxy,
	Binaries:    []string{"curl"},
	Policy: bbox.NetworkPolicy{
		AllowHostPatterns: []string{`^example[.]com$`},
		AllowHTTPMethods:  []string{"GET"},
		AllowConnect:      true,
		AllowConnectPorts: []string{"443"},
	},
})
```

In proxy mode, bbox injects `HTTP_PROXY`, `http_proxy`, `HTTPS_PROXY`, and `https_proxy` for sandboxed runs. `Sandbox.ProxyAddr()` and `Sandbox.ProxyURL()` report the helper's effective proxy endpoint.

Transparent mode is opt-in and requires manager-wide MITM support:

```go
manager, err := bbox.NewProxyManager(bbox.ProxyOptions{
	MaxRequestBodyBytes: 64 << 10,
	MITM:                bbox.MITMOptions{Enabled: true},
})

sandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
	Name:        "transparent-demo",
	TrafficMode: bbox.TrafficModeTransparent,
	Binaries:    []string{"curl"},
	Policy: bbox.NetworkPolicy{
		AllowHostPatterns: []string{`^api[.]github[.]com$`},
		AllowHTTPMethods:  []string{"GET"},
		AllowPathPatterns: []string{`^/repos/`},
	},
})
```

In transparent mode, bbox does not inject proxy environment variables. Instead, the helper owns sandbox-local listeners for DNS on `127.0.0.1:53`, HTTP on `127.0.0.1:80`, and HTTPS MITM on `127.0.0.1:443`. `Sandbox.ProxyAddr()` and `Sandbox.ProxyURL()` intentionally return empty strings in this mode.

Transparent mode limitations:

- only hostname-based HTTP on `:80`
- only hostname-based HTTPS on `:443`
- no IP-literal destinations such as `https://1.1.1.1/`
- no non-default ports such as `:8080` or `:8443`
- no QUIC / HTTP/3
- no arbitrary non-HTTP TCP protocols

## Access Audit And Logging

Each sandbox tracks attempted outbound hosts. Call `Sandbox.AccessedDomains()` to fetch a snapshot of the aggregated audit state, including attempt counts, the most recent result/error, last seen time, last port, and whether HTTP, CONNECT, or MITM requests were observed.

Every request attempt also emits a structured access log entry. By default, `bbox` writes newline-delimited JSON to stdout. Provide `ProxyOptions.AccessLogger` to route entries to your own logger instead of stdout.

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
	Seccomp: bbox.SeccompOptions{
		Profile: bbox.SeccompProfileBaseline,
	},
	Mounts: []bbox.Mount{
		{Source: "/tmp", Target: "/workspace", ReadOnly: false},
	},
		Policy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^example[.]com$`},
			AllowHTTPMethods:  []string{"GET"},
			AllowPathPatterns: []string{`^/$`},
			AllowConnect:      true,
			AllowConnectPorts: []string{"443"},
		},
		WorkDir: "/workspace",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer sandbox.Close()

	log.Printf("sandbox proxy: %s", sandbox.ProxyURL())

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
- `ProxyOptions.ListenAddr` sets the sandbox-local proxy listen address used by proxy-mode helpers. Leave it empty to use `127.0.0.1:31111`, or set it to `127.0.0.1:0` to let the kernel choose a free port. The sandbox runtime env is updated from the helper's reported bound address.
- Proxy-mode sandbox runs export `HTTP_PROXY` and `HTTPS_PROXY` pointing at the helper's sandbox-local listener. Transparent-mode runs do not inject proxy env vars.
- Payload processes do not inherit the host bridge file descriptor.
- Seccomp is enabled by default with the baseline profile. Use `SandboxOptions.Seccomp.Profile` to switch to `restricted`, `custom`, or disable seccomp entirely.
- Per-sandbox policy is enforced on the host before outbound requests are made.
- Use `NetworkPolicy.AllowConnect` and `NetworkPolicy.AllowConnectPorts` to allow CONNECT tunnels to specific destination ports.
- When `ProxyOptions.MITM.Enabled` is true, HTTPS requests are intercepted locally in the helper and checked against per-sandbox path, header, and body policy before the host performs the upstream request.
- Transparent mode requires the helper to bind `127.0.0.1:53`, `127.0.0.1:80`, and `127.0.0.1:443` inside the sandbox network namespace.
