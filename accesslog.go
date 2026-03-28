package bbox

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type accessEvent struct {
	Time       time.Time
	SandboxID  string
	Kind       string
	Host       string
	Port       int
	Method     string
	Path       string
	Allowed    bool
	StatusCode int
	Result     string
	Error      string
}

func (e accessEvent) toAccessLogEntry() AccessLogEntry {
	return AccessLogEntry{
		Time:       e.Time,
		SandboxID:  e.SandboxID,
		Kind:       e.Kind,
		Host:       e.Host,
		Port:       e.Port,
		Method:     e.Method,
		Path:       e.Path,
		Allowed:    e.Allowed,
		StatusCode: e.StatusCode,
		Result:     e.Result,
		Error:      e.Error,
	}
}

type managerAuditState struct {
	sandboxes map[string]map[string]*AccessedDomain
}

var auditStateByManager sync.Map

func auditStateLocked(m *ProxyManager) *managerAuditState {
	if m == nil {
		return nil
	}
	if state, ok := auditStateByManager.Load(m); ok {
		return state.(*managerAuditState)
	}
	state := &managerAuditState{sandboxes: make(map[string]map[string]*AccessedDomain)}
	actual, _ := auditStateByManager.LoadOrStore(m, state)
	return actual.(*managerAuditState)
}

func initAuditStateLocked(m *ProxyManager, sandboxID string) {
	if m == nil || sandboxID == "" {
		return
	}
	state := auditStateLocked(m)
	if state == nil {
		return
	}
	if state.sandboxes == nil {
		state.sandboxes = make(map[string]map[string]*AccessedDomain)
	}
	if _, exists := state.sandboxes[sandboxID]; !exists {
		state.sandboxes[sandboxID] = make(map[string]*AccessedDomain)
	}
}

func removeAuditStateLocked(m *ProxyManager, sandboxID string) {
	if m == nil || sandboxID == "" {
		return
	}
	stateValue, ok := auditStateByManager.Load(m)
	if !ok {
		return
	}
	state := stateValue.(*managerAuditState)
	if state.sandboxes == nil {
		return
	}
	delete(state.sandboxes, sandboxID)
	if len(state.sandboxes) == 0 {
		auditStateByManager.Delete(m)
	}
}

func normalizeHostPort(host string, port int) (string, int) {
	trimmed := strings.TrimSpace(host)
	if trimmed == "" {
		return "", port
	}
	normalizedHost := trimmed
	normalizedPort := port

	if splitHost, splitPort, err := net.SplitHostPort(trimmed); err == nil {
		normalizedHost = splitHost
		if parsed, err := strconv.Atoi(splitPort); err == nil {
			normalizedPort = parsed
		}
	}

	return normalizedHost, normalizedPort
}

func updateAuditStateLocked(state *managerAuditState, event accessEvent) {
	if state == nil || event.SandboxID == "" {
		return
	}
	if state.sandboxes == nil {
		state.sandboxes = make(map[string]map[string]*AccessedDomain)
	}
	sandboxState, ok := state.sandboxes[event.SandboxID]
	if !ok {
		sandboxState = make(map[string]*AccessedDomain)
		state.sandboxes[event.SandboxID] = sandboxState
	}

	host, port := normalizeHostPort(event.Host, event.Port)
	if host == "" {
		host = event.Host
	}

	entry, ok := sandboxState[host]
	if !ok {
		entry = &AccessedDomain{Host: host}
		sandboxState[host] = entry
	}

	entry.Attempts++
	entry.LastResult = event.Result
	entry.LastError = event.Error
	entry.LastSeenAt = event.Time
	entry.LastPort = port

	switch event.Kind {
	case "connect":
		entry.ConnectSeen = true
	case "http":
		entry.HTTPSeen = true
	case "mitm":
		entry.MITMSeen = true
	}
}

func snapshotAccessedDomains(state map[string]*AccessedDomain) []AccessedDomain {
	if len(state) == 0 {
		return []AccessedDomain{}
	}
	out := make([]AccessedDomain, 0, len(state))
	for _, entry := range state {
		if entry == nil {
			continue
		}
		out = append(out, *entry)
	}
	return out
}
