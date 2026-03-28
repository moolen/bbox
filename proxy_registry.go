package bbox

import (
	"fmt"
	"sync"
)

type sandboxRegistry struct {
	mu            sync.RWMutex
	defaultPolicy *compiledPolicy
	sandboxes     map[string]*Sandbox
	policies      map[string]*compiledPolicy
}

func newSandboxRegistry(defaultPolicy *compiledPolicy) *sandboxRegistry {
	return &sandboxRegistry{
		defaultPolicy: defaultPolicy,
		sandboxes:     make(map[string]*Sandbox),
		policies:      make(map[string]*compiledPolicy),
	}
}

func (r *sandboxRegistry) Register(id string, policy *compiledPolicy) error {
	if id == "" {
		return fmt.Errorf("sandbox ID is required")
	}
	if policy == nil {
		policy = r.defaultPolicy
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.sandboxes[id]; exists {
		return fmt.Errorf("sandbox %q is already registered", id)
	}

	r.sandboxes[id] = nil
	r.policies[id] = policy
	return nil
}

func (r *sandboxRegistry) Attach(id string, sandbox *Sandbox) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.sandboxes[id]; !exists {
		return fmt.Errorf("sandbox %q is not registered", id)
	}
	r.sandboxes[id] = sandbox
	return nil
}

func (r *sandboxRegistry) Unregister(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.sandboxes, id)
	delete(r.policies, id)
}

func (r *sandboxRegistry) Policy(id string) (*compiledPolicy, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	policy, ok := r.policies[id]
	return policy, ok
}

func (r *sandboxRegistry) Has(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, ok := r.sandboxes[id]
	return ok
}

func (r *sandboxRegistry) Sandbox(id string) (*Sandbox, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	sandbox, ok := r.sandboxes[id]
	return sandbox, ok
}

func (r *sandboxRegistry) AttachedSandboxes() []*Sandbox {
	r.mu.RLock()
	defer r.mu.RUnlock()

	sandboxes := make([]*Sandbox, 0, len(r.sandboxes))
	for _, sandbox := range r.sandboxes {
		if sandbox != nil {
			sandboxes = append(sandboxes, sandbox)
		}
	}
	return sandboxes
}
