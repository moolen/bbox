package bbox

import "time"

func (m *ProxyManager) recordAccessEvent(event accessEvent) {
	if m == nil || event.SandboxID == "" {
		return
	}
	if event.Time.IsZero() {
		event.Time = time.Now()
	}
	if event.TrafficMode == "" {
		event.TrafficMode = m.trafficModeForSandbox(event.SandboxID)
	}
	event.TrafficMode = normalizeTrafficMode(event.TrafficMode)
	entry := event.toAccessLogEntry()

	m.mu.Lock()
	if !m.registry.Has(event.SandboxID) {
		m.mu.Unlock()
		return
	}
	updateAuditStateLocked(auditStateLocked(m), event)
	logger := m.accessLogger
	m.mu.Unlock()

	if logger != nil {
		func() {
			defer func() {
				_ = recover()
			}()
			logger.LogAccess(entry)
		}()
	}
}

func (m *ProxyManager) trafficModeForSandbox(sandboxID string) TrafficMode {
	if m == nil || sandboxID == "" {
		return TrafficModeProxy
	}

	sandbox, ok := m.registry.Sandbox(sandboxID)
	if !ok || sandbox == nil {
		return TrafficModeProxy
	}

	return normalizeTrafficMode(sandbox.trafficMode)
}

func (m *ProxyManager) accessedDomainsSnapshot(sandboxID string) []AccessedDomain {
	if m == nil || sandboxID == "" {
		return []AccessedDomain{}
	}

	m.mu.RLock()
	stateValue, ok := auditStateByManager.Load(m)
	if !ok {
		m.mu.RUnlock()
		return []AccessedDomain{}
	}
	state := stateValue.(*managerAuditState)
	sandboxState, ok := state.sandboxes[sandboxID]
	if !ok || sandboxState == nil {
		m.mu.RUnlock()
		return []AccessedDomain{}
	}
	snapshot := snapshotAccessedDomains(sandboxState.domains)
	m.mu.RUnlock()
	return snapshot
}
