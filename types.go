package bbox

import (
	"net/http"
	"sync"
)

type ProxyOptions struct {
	NetworkPolicy NetworkPolicy
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
