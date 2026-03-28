package bbox

import (
	"net/http"
	"sync"
	"sync/atomic"
)

type ProxyOptions struct {
	// ListenAddr is the sandbox-local proxy listen address passed to each helper.
	// If empty, bbox uses 127.0.0.1:31111. Use 127.0.0.1:0 to request an
	// ephemeral port and read the effective address from Sandbox.ProxyAddr.
	ListenAddr string
	// NetworkPolicy is the default policy inherited by sandboxes that do not
	// supply their own SandboxOptions.Policy.
	NetworkPolicy NetworkPolicy
	// MITM configures proxy-wide man-in-the-middle handling.
	MITM MITMOptions
}

// MITMOptions configures manager-wide MITM behavior.
type MITMOptions struct {
	// Enabled enables MITM handling for HTTP CONNECT traffic.
	Enabled bool
	// MaxRequestBodyBytes caps buffered request bodies when inspecting traffic.
	MaxRequestBodyBytes int64
}

// Mount binds a host path into the sandbox.
type Mount struct {
	// Source is the absolute host path to bind into the sandbox.
	Source string
	// Target is the absolute path inside the sandbox.
	Target string
	// ReadOnly controls whether the bind mount is read-only.
	ReadOnly bool
}

// SandboxOptions configures a new sandbox instance.
type SandboxOptions struct {
	// Name selects the sandbox identifier. If empty, bbox generates one.
	Name string
	// Binaries lists host binaries to stage into the sandbox root.
	Binaries []string
	// Mounts declares additional bind mounts inside the sandbox.
	Mounts []Mount
	// Env adds process environment entries for runs in this sandbox.
	Env []string
	// Policy overrides the manager default for this sandbox when non-zero.
	Policy NetworkPolicy
	// WorkDir is the default working directory for sandbox.Run.
	WorkDir string
}

// RunOptions configures an individual process execution inside a sandbox.
type RunOptions struct {
	// Env adds or overrides environment entries for a single run.
	Env []string
	// WorkDir overrides the sandbox default working directory for one run.
	WorkDir string
}

// RunResult contains the exit status and captured output from a sandboxed
// process.
type RunResult struct {
	// ExitCode is the process exit status, or -1 when execution failed before
	// a process exit code was available.
	ExitCode int
	// Stdout is the captured standard output stream.
	Stdout []byte
	// Stderr is the captured standard error stream.
	Stderr []byte
}

// NetworkPolicy defines the host-side egress rules applied to one sandbox.
type NetworkPolicy struct {
	// AllowHostPatterns is a regex allowlist matched against destination hosts.
	AllowHostPatterns []string
	// DenyHostPatterns is a regex denylist applied before the allowlist.
	DenyHostPatterns []string
	// AllowHTTPMethods restricts plain HTTP requests to the listed methods.
	AllowHTTPMethods []string
	// AllowConnect enables HTTP CONNECT tunneling.
	AllowConnect bool
	// AllowConnectPorts restricts CONNECT to the listed destination ports or
	// port ranges.
	AllowConnectPorts []string
}

// ProxyManager owns the shared proxy policy state and creates sandboxes that
// route traffic through it.
type ProxyManager struct {
	mu              sync.RWMutex
	policy          *compiledPolicy
	sandboxes       map[string]*Sandbox
	sandboxPolicies map[string]*compiledPolicy
	transport       *http.Transport
	listenAddr      string
	mitm            MITMOptions
	mitmCA          *mitmCA
	caCertPEM       []byte
	nextSandboxID   atomic.Uint64

	helperBinaryOnce sync.Once
	helperBinaryPath string
	helperBinaryDir  string
	helperBinaryErr  error

	closeOnce sync.Once
}
