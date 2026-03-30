package bbox

import (
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// AccessLogger receives per-request access log entries.
type AccessLogger interface {
	LogAccess(AccessLogEntry)
}

// AccessLogEntry describes a single access attempt.
type AccessLogEntry struct {
	Time        time.Time
	SandboxID   string
	TrafficMode TrafficMode
	Kind        string
	Host        string
	Port        int
	Method      string
	Path        string
	Allowed     bool
	StatusCode  int
	Result      string
	Error       string
}

// AccessedDomain aggregates access attempts for a host.
type AccessedDomain struct {
	Host        string
	TrafficMode TrafficMode
	Attempts    int
	LastResult  string
	LastError   string
	LastSeenAt  time.Time
	LastPort    int
	ConnectSeen bool
	HTTPSeen    bool
	MITMSeen    bool
}

type ProxyOptions struct {
	// ListenAddr is the sandbox-local proxy listen address passed to each helper.
	// If empty, bbox uses 127.0.0.1:31111. Use 127.0.0.1:0 to request an
	// ephemeral port and read the effective address from Sandbox.ProxyAddr.
	ListenAddr string
	// MaxRequestBodyBytes caps buffered request bodies across proxy and MITM
	// flows. Zero uses the secure default.
	MaxRequestBodyBytes int64
	// MaxResponseBodyBytes caps buffered upstream response bodies across proxy
	// and MITM flows. Zero uses the secure default.
	MaxResponseBodyBytes int64
	// NetworkPolicy is the default policy inherited by sandboxes that do not
	// supply their own SandboxOptions.Policy.
	NetworkPolicy NetworkPolicy
	// MITM configures proxy-wide man-in-the-middle handling.
	MITM MITMOptions
	// AccessLogger receives per-request access log entries.
	AccessLogger AccessLogger
}

// MITMOptions configures manager-wide MITM behavior.
type MITMOptions struct {
	// Enabled enables MITM handling for HTTP CONNECT traffic.
	Enabled bool
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

// TrafficMode controls how sandbox traffic is handled.
type TrafficMode string

const (
	// TrafficModeProxy injects proxy environment variables into sandboxed runs.
	TrafficModeProxy TrafficMode = "proxy"
	// TrafficModeTransparent relies on transparent proxying without env injection.
	TrafficModeTransparent TrafficMode = "transparent"
)

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
	// TrafficMode selects proxy env injection vs transparent mode (defaults to proxy).
	TrafficMode TrafficMode
	// Policy overrides the manager default for this sandbox when non-zero.
	Policy NetworkPolicy
	// WorkDir is the default working directory for sandbox.Run.
	WorkDir string
	// Seccomp configures seccomp filtering for this sandbox. The zero value
	// enables the baseline built-in profile.
	Seccomp SeccompOptions
}

// TerminalSize describes terminal dimensions for interactive runs.
type TerminalSize struct {
	Rows uint16
	Cols uint16
}

// RunOptions configures an individual process execution inside a sandbox.
type RunOptions struct {
	// Env adds or overrides environment entries for a single run.
	Env []string
	// WorkDir overrides the sandbox default working directory for one run.
	WorkDir string
	// Interactive enables stdin/stdout/stderr streaming instead of buffered
	// output only.
	Interactive bool
	// Stdin is forwarded to the sandboxed process when interactive execution is
	// enabled.
	Stdin io.Reader
	// Stdout receives streamed stdout frames during interactive execution.
	Stdout io.Writer
	// Stderr receives streamed stderr frames during interactive execution.
	Stderr io.Writer
	// Terminal requests a real PTY-backed terminal session for the payload.
	Terminal bool
	// TerminalSize is the initial PTY size for terminal-backed runs.
	TerminalSize TerminalSize
	// Resize delivers PTY resize updates for terminal-backed runs.
	Resize <-chan TerminalSize
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
	// AllowIPCIDRs is a CIDR allowlist matched against IP literal destinations.
	AllowIPCIDRs []string
	// DenyIPCIDRs is a CIDR denylist applied before the CIDR allowlist.
	DenyIPCIDRs []string
	// AllowHTTPMethods restricts plain HTTP requests to the listed methods.
	AllowHTTPMethods []string
	// AllowConnect enables HTTP CONNECT tunneling.
	AllowConnect bool
	// AllowConnectPorts restricts CONNECT to the listed destination ports or
	// port ranges.
	AllowConnectPorts []string
	// AllowPathPatterns is a regex allowlist matched against decrypted request
	// paths.
	AllowPathPatterns []string
	// DenyPathPatterns is a regex denylist matched against decrypted request
	// paths.
	DenyPathPatterns []string
	// AllowHeaderPatterns is a map of header names to regex allowlists for their
	// values.
	AllowHeaderPatterns map[string][]string
	// DenyHeaderPatterns is a map of header names to regex denylists for their
	// values.
	DenyHeaderPatterns map[string][]string
	// AllowBodyPatterns is a regex allowlist matched against the bounded request
	// body.
	AllowBodyPatterns []string
	// DenyBodyPatterns is a regex denylist matched against the bounded request
	// body.
	DenyBodyPatterns []string
}

// ProxyManager owns the shared proxy policy state and creates sandboxes that
// route traffic through it.
type ProxyManager struct {
	mu                     sync.RWMutex
	registry               *sandboxRegistry
	resolver               *helperBinaryResolver
	transport              *http.Transport
	accessLogger           AccessLogger
	listenAddr             string
	requestBodyLimitBytes  int64
	responseBodyLimitBytes int64
	mitm                   MITMOptions
	mitmCA                 *mitmCA
	caCertPEM              []byte
	nextSandboxID          atomic.Uint64

	closeOnce sync.Once
}
