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
	Time               time.Time
	SandboxID          string
	TrafficMode        TrafficMode
	Kind               string
	Protocol           string `json:"Protocol,omitempty"`
	ProtocolSource     string `json:"ProtocolSource,omitempty"`
	ProtocolConfidence string `json:"ProtocolConfidence,omitempty"`
	Host               string
	Port               int
	Method             string
	Path               string
	Allowed            bool
	StatusCode         int
	Result             string
	Error              string
	PolicyMode         PolicyMode
	PolicyAllowed      bool
	PolicyViolations   []string
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

// PolicyMode controls whether policy decisions are enforced or audited.
type PolicyMode string

const (
	PolicyModeEnforce PolicyMode = "enforce"
	PolicyModeAudit   PolicyMode = "audit"
)

// ReportingOptions controls optional policy reporting outputs.
type ReportingOptions struct {
	PolicyViolations bool
	AccessSummary    bool
	RequestSummary   bool
}

// AccessSummary contains aggregate access snapshots.
type AccessSummary struct {
	Hosts    []AccessedHostSummary
	Requests []RequestAggregate
}

// AccessedHostSummary aggregates access attempts for a host.
type AccessedHostSummary struct {
	Host               string
	TrafficMode        TrafficMode
	Attempts           int
	LastResult         string
	LastError          string
	LastSeenAt         time.Time
	LastPort           int
	ConnectSeen        bool
	HTTPSeen           bool
	MITMSeen           bool
	DNSSeen            bool
	PolicyViolations   int
	PolicyAllowedCount int
	PolicyDeniedCount  int
}

// RequestAggregate is a request-level aggregate reporting row.
type RequestAggregate struct {
	Kind               string
	Host               string
	Port               int
	Method             string
	Path               string
	Attempts           int
	AllowedCount       int
	DeniedCount        int
	PolicyAllowedCount int
	PolicyDeniedCount  int
	LastSeenAt         time.Time
	LastStatusCode     int
	LastError          string
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
	// PolicyMode configures default manager policy behavior for sandboxes.
	PolicyMode PolicyMode
	// Reporting configures default manager reporting behavior for sandboxes.
	Reporting ReportingOptions
	// MITM configures proxy-wide man-in-the-middle handling.
	MITM MITMOptions
	// AccessLogger receives per-request access log entries.
	AccessLogger AccessLogger
	// DockerSocket configures manager-wide Docker socket mediation defaults.
	DockerSocket DockerSocketOptions
}

// MITMOptions configures manager-wide MITM behavior.
type MITMOptions struct {
	// Enabled enables MITM handling for HTTP CONNECT traffic.
	Enabled bool
}

type MountType string

const (
	MountTypeBind     MountType = "bind"
	MountTypeEmptyDir MountType = "empty_dir"
)

// Mount defines a mount inside the sandbox.
type Mount struct {
	// Type declares the mount behavior.
	Type MountType
	// Source is the absolute host path to bind into the sandbox.
	Source string
	// Target is the absolute path inside the sandbox.
	Target string
	// ReadOnly controls whether the bind mount is read-only.
	ReadOnly bool
	// Mode configures permissions for mount types that create directories.
	Mode uint32
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
	// PolicyMode overrides the manager default policy mode when non-zero.
	PolicyMode PolicyMode
	// Reporting overrides the manager default reporting behavior when non-zero.
	Reporting ReportingOptions
	// WorkDir is the default working directory for sandbox.Run.
	WorkDir string
	// Seccomp configures seccomp filtering for this sandbox. The zero value
	// enables the baseline built-in profile.
	Seccomp SeccompOptions
	// DockerSocket overrides manager Docker socket mediation settings when
	// non-zero.
	DockerSocket DockerSocketOptions
	// DockerBuild enables the in-sandbox docker-build compatibility path.
	DockerBuild DockerBuildOptions
}

// DockerSocketOptions configures Docker socket mediation for a manager or
// sandbox.
type DockerSocketOptions struct {
	Enabled          bool
	MountPath        string
	TargetSocketPath string
	Policy           DockerSocketPolicy
}

// DockerRuleAction controls whether a matching rule allows or denies a
// request.
type DockerRuleAction string

const (
	DockerRuleActionAllow DockerRuleAction = "allow"
	DockerRuleActionDeny  DockerRuleAction = "deny"
)

// DockerOperation is a normalized Docker API operation identifier.
type DockerOperation string

// DockerSocketPolicy defines ordered allow/deny rules for Docker socket
// mediation.
type DockerSocketPolicy struct {
	DefaultAction DockerRuleAction
	Rules         []DockerSocketRule
}

// DockerSocketRule defines one ordered Docker socket policy rule.
type DockerSocketRule struct {
	Action     DockerRuleAction
	Operations []DockerOperation
	HTTP       *DockerHTTPMatch
	Build      *DockerBuildMatch
}

// DockerHTTPMatch provides raw HTTP request matching for Docker policies.
type DockerHTTPMatch struct {
	Methods      []string
	PathPatterns []string
}

// DockerBuildContextMatch constrains which build context forms a rule allows.
type DockerBuildContextMatch string

const (
	DockerBuildContextMatchLocalOnly DockerBuildContextMatch = "local_only"
)

// DockerBuildMatch provides build-specific request matching.
type DockerBuildMatch struct {
	Context         DockerBuildContextMatch
	DockerfilePaths []string
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
	// Rules is the ordered list of allow rules. A request is allowed when at
	// least one rule matches. The zero value denies all traffic in enforce mode.
	Rules []PolicyRule
}

// PolicyRule describes one allow rule within a NetworkPolicy.
type PolicyRule struct {
	// HostPatterns is a regex allowlist matched against normalized destination
	// hostnames.
	HostPatterns []string
	// IPCIDRs is a CIDR allowlist matched against IP literal destinations.
	IPCIDRs []string
	// HTTPMethods restricts plain or MITM-visible HTTP requests to the listed
	// methods.
	HTTPMethods []string
	// ConnectPorts restricts explicit proxy CONNECT traffic to the listed
	// destination ports or port ranges.
	ConnectPorts []string
	// PathPatterns is a regex allowlist matched against visible request paths.
	PathPatterns []string
	// HeaderPatterns is a map of header names to regex allowlists for their
	// values.
	HeaderPatterns map[string][]string
	// BodyPatterns is a regex allowlist matched against the bounded inspected
	// request body.
	BodyPatterns []string
}

// ProxyManager owns the shared proxy policy state and creates sandboxes that
// route traffic through it.
type ProxyManager struct {
	mu                     sync.RWMutex
	registry               *sandboxRegistry
	resolver               *runtimeBinaryResolver
	transport              *http.Transport
	accessLogger           AccessLogger
	listenAddr             string
	requestBodyLimitBytes  int64
	responseBodyLimitBytes int64
	mitm                   MITMOptions
	policyMode             PolicyMode
	reporting              ReportingOptions
	dockerSocket           DockerSocketOptions
	dockerSocketPolicy     *compiledDockerSocketPolicy
	mitmCA                 *mitmCA
	caCertPEM              []byte
	nextSandboxID          atomic.Uint64

	closeOnce sync.Once
}
