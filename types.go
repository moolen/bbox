package bbox

import (
	"net/http"
	"sync"
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
	Binaries []string
	Mounts   []Mount
	Env      []string
	Policy   NetworkPolicy
	WorkDir  string
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
	sandboxes       map[string]struct{}
	sandboxPolicies map[string]*compiledPolicy
	transport       *http.Transport
}
