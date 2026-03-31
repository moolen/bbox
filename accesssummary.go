package bbox

import (
	"sort"
	"strconv"
	"strings"
)

type sandboxAuditState struct {
	domains  map[string]*AccessedDomain
	hosts    map[string]*accessedHostSummaryState
	requests map[string]*requestAggregateState
}

type accessedHostSummaryState struct {
	AccessedHostSummary
}

type requestAggregateState struct {
	RequestAggregate
}

func newSandboxAuditState() *sandboxAuditState {
	return &sandboxAuditState{
		domains:  make(map[string]*AccessedDomain),
		hosts:    make(map[string]*accessedHostSummaryState),
		requests: make(map[string]*requestAggregateState),
	}
}

func recordHostSummaryAggregate(state map[string]*accessedHostSummaryState, event accessEvent) {
	if state == nil {
		return
	}

	host, port := normalizeHostPort(event.Host, event.Port)
	if host == "" {
		host = strings.ToLower(event.Host)
	}

	entry, ok := state[host]
	if !ok {
		entry = &accessedHostSummaryState{
			AccessedHostSummary: AccessedHostSummary{Host: host},
		}
		state[host] = entry
	}

	entry.TrafficMode = normalizeTrafficMode(event.TrafficMode)
	entry.Attempts++
	entry.LastResult = event.Result
	entry.LastError = event.Error
	entry.LastSeenAt = event.Time
	entry.LastPort = port

	switch event.Kind {
	case "connect", "transparent_connect":
		entry.ConnectSeen = true
	case "http":
		entry.HTTPSeen = true
	case "mitm":
		entry.MITMSeen = true
	case "dns":
		entry.DNSSeen = true
	}

	if event.PolicyAllowed {
		entry.PolicyAllowedCount++
	} else {
		entry.PolicyDeniedCount++
	}
	entry.PolicyViolations += len(event.PolicyViolations)
}

func recordRequestAggregate(state map[string]*requestAggregateState, event accessEvent) {
	if state == nil {
		return
	}

	host, port := normalizeHostPort(event.Host, event.Port)
	if host == "" {
		host = strings.ToLower(event.Host)
	}
	key := requestAggregateKey(event.Kind, host, port, event.Method, event.Path)

	entry, ok := state[key]
	if !ok {
		entry = &requestAggregateState{
			RequestAggregate: RequestAggregate{
				Kind:   event.Kind,
				Host:   host,
				Port:   port,
				Method: event.Method,
				Path:   event.Path,
			},
		}
		state[key] = entry
	}

	entry.Attempts++
	if event.Allowed {
		entry.AllowedCount++
	} else {
		entry.DeniedCount++
	}
	if event.PolicyAllowed {
		entry.PolicyAllowedCount++
	} else {
		entry.PolicyDeniedCount++
	}
	entry.LastSeenAt = event.Time
	entry.LastStatusCode = event.StatusCode
	entry.LastError = event.Error
}

func snapshotHostSummaries(state map[string]*accessedHostSummaryState) []AccessedHostSummary {
	if len(state) == 0 {
		return []AccessedHostSummary{}
	}

	out := make([]AccessedHostSummary, 0, len(state))
	for _, entry := range state {
		if entry == nil {
			continue
		}
		out = append(out, entry.AccessedHostSummary)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Host < out[j].Host
	})
	return out
}

func snapshotRequestAggregates(state map[string]*requestAggregateState) []RequestAggregate {
	if len(state) == 0 {
		return []RequestAggregate{}
	}

	out := make([]RequestAggregate, 0, len(state))
	for _, entry := range state {
		if entry == nil {
			continue
		}
		out = append(out, entry.RequestAggregate)
	}
	sort.Slice(out, func(i, j int) bool {
		left := out[i]
		right := out[j]
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		if left.Host != right.Host {
			return left.Host < right.Host
		}
		if left.Port != right.Port {
			return left.Port < right.Port
		}
		if left.Method != right.Method {
			return left.Method < right.Method
		}
		return left.Path < right.Path
	})
	return out
}

func requestAggregateKey(kind, host string, port int, method, path string) string {
	return strings.Join([]string{
		kind,
		host,
		strconv.Itoa(port),
		method,
		path,
	}, "\x00")
}

func (m *ProxyManager) accessSummarySnapshot(sandboxID string) AccessSummary {
	if m == nil || sandboxID == "" {
		return AccessSummary{
			Hosts:    []AccessedHostSummary{},
			Requests: []RequestAggregate{},
		}
	}

	m.mu.RLock()
	stateValue, ok := auditStateByManager.Load(m)
	if !ok {
		m.mu.RUnlock()
		return AccessSummary{
			Hosts:    []AccessedHostSummary{},
			Requests: []RequestAggregate{},
		}
	}
	state := stateValue.(*managerAuditState)
	sandboxState, ok := state.sandboxes[sandboxID]
	if !ok || sandboxState == nil {
		m.mu.RUnlock()
		return AccessSummary{
			Hosts:    []AccessedHostSummary{},
			Requests: []RequestAggregate{},
		}
	}
	snapshot := AccessSummary{
		Hosts:    snapshotHostSummaries(sandboxState.hosts),
		Requests: snapshotRequestAggregates(sandboxState.requests),
	}
	m.mu.RUnlock()
	return snapshot
}
