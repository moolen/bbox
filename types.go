package bbox

import (
	"net/http"
	"sync"
	"sync/atomic"
)

type ProxyOptions struct {
	NetworkPolicy NetworkPolicy
}

type Mount struct {
	Source   string
	Target   string
	ReadOnly bool
}

type SandboxOptions struct {
	Name     string
	Binaries []string
	Mounts   []Mount
	Env      []string
	Policy   NetworkPolicy
	WorkDir  string
}

type RunOptions struct {
	Env     []string
	WorkDir string
}

type RunResult struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
}

type NetworkPolicy struct {
	AllowHostPatterns []string
	DenyHostPatterns  []string
	AllowHTTPMethods  []string
	AllowConnect      bool
}

type ProxyManager struct {
	mu              sync.RWMutex
	policy          *compiledPolicy
	sandboxes       map[string]*Sandbox
	sandboxPolicies map[string]*compiledPolicy
	transport       *http.Transport
	nextSandboxID   atomic.Uint64

	helperBinaryOnce sync.Once
	helperBinaryPath string
	helperBinaryDir  string
	helperBinaryErr  error

	closeOnce sync.Once
}
