package bbox

import (
	"fmt"
	"net/http"
)

func newProxyManager(policy *compiledPolicy) *ProxyManager {
	return &ProxyManager{
		policy:          policy,
		sandboxes:       make(map[string]struct{}),
		sandboxPolicies: make(map[string]*compiledPolicy),
		transport:       cloneDefaultTransport(),
	}
}

func cloneDefaultTransport() *http.Transport {
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		return base.Clone()
	}
	return &http.Transport{}
}

func (m *ProxyManager) registerSandbox(sandboxID string, policy *compiledPolicy) error {
	if sandboxID == "" {
		return fmt.Errorf("sandbox ID is required")
	}
	if policy == nil {
		policy = m.policy
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sandboxes[sandboxID]; exists {
		return fmt.Errorf("sandbox %q is already registered", sandboxID)
	}

	m.sandboxes[sandboxID] = struct{}{}
	m.sandboxPolicies[sandboxID] = policy
	return nil
}

func (m *ProxyManager) unregisterSandbox(sandboxID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sandboxes, sandboxID)
	delete(m.sandboxPolicies, sandboxID)
}

func (m *ProxyManager) policyForSandbox(sandboxID string) (*compiledPolicy, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	policy, ok := m.sandboxPolicies[sandboxID]
	return policy, ok
}

func (m *ProxyManager) outboundTransport() *http.Transport {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.transport
}
