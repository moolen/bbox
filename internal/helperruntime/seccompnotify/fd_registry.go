package seccompnotify

import (
	"sync"

	"golang.org/x/sys/unix"
)

const (
	minManagedHelperFD      = 3
	minManagedTCPChildFD    = 32
	minManagedUDPChildFD    = 128
	minManagedReadWriteFDLo = minManagedUDPChildFD
)

type FDRegistry struct {
	mu     sync.RWMutex
	states map[fdRegistryKey]SocketState
}

type fdRegistryKey struct {
	pid int
	fd  int
}

func NewFDRegistry() *FDRegistry {
	return &FDRegistry{
		states: make(map[fdRegistryKey]SocketState),
	}
}

func (r *FDRegistry) Insert(state SocketState) {
	r.InsertForPID(state.ChildPID, state)
}

func (r *FDRegistry) InsertForPID(pid int, state SocketState) {
	if r == nil || state.ChildFD < 0 {
		return
	}
	state.ChildPID = normalizeRegistryPID(pid)

	r.mu.Lock()
	r.states[fdRegistryKey{pid: state.ChildPID, fd: state.ChildFD}] = state
	r.mu.Unlock()
}

func (r *FDRegistry) Lookup(childFD int) (SocketState, bool) {
	return r.LookupForPID(0, childFD)
}

func (r *FDRegistry) LookupForPID(pid int, childFD int) (SocketState, bool) {
	if r == nil || childFD < 0 {
		return SocketState{}, false
	}

	r.mu.RLock()
	key, ok := r.lookupKeyLocked(normalizeRegistryPID(pid), childFD)
	if !ok {
		r.mu.RUnlock()
		return SocketState{}, false
	}
	state := r.states[key]
	r.mu.RUnlock()
	return state, ok
}

func (r *FDRegistry) Dup(sourceFD, targetFD int) error {
	return r.DupForPID(0, sourceFD, targetFD)
}

func (r *FDRegistry) DupForPID(pid int, sourceFD, targetFD int) error {
	if r == nil {
		return unix.EBADF
	}
	if sourceFD < 0 || targetFD < 0 {
		return unix.EBADF
	}
	if sourceFD == targetFD {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	normalizedPID := normalizeRegistryPID(pid)
	sourceKey, ok := r.lookupKeyLocked(normalizedPID, sourceFD)
	if !ok {
		return unix.EBADF
	}
	targetKey := fdRegistryKey{pid: normalizedPID, fd: targetFD}
	state := r.states[sourceKey]

	duplicated := state
	duplicated.ChildPID = normalizedPID
	duplicated.ChildFD = targetFD
	if state.HelperFD >= minManagedHelperFD {
		helperFD, err := unix.Dup(state.HelperFD)
		if err != nil {
			return err
		}
		duplicated.HelperFD = helperFD
	}

	if existing, ok := r.states[targetKey]; ok {
		// Avoid closing the source helper fd when state was manually copied.
		if existing.HelperFD != state.HelperFD {
			closeManagedHelperFD(existing.HelperFD)
		}
	}
	r.states[targetKey] = duplicated
	return nil
}

func (r *FDRegistry) Close(childFD int) {
	r.CloseForPID(0, childFD)
}

func (r *FDRegistry) CloseForPID(pid int, childFD int) {
	if r == nil || childFD < 0 {
		return
	}

	r.mu.Lock()
	key, ok := r.lookupKeyLocked(normalizeRegistryPID(pid), childFD)
	if !ok {
		r.mu.Unlock()
		return
	}
	if state, ok := r.states[key]; ok {
		closeManagedHelperFD(state.HelperFD)
	}
	delete(r.states, key)
	r.mu.Unlock()
}

func closeManagedHelperFD(helperFD int) {
	if helperFD >= minManagedHelperFD {
		_ = unix.Close(helperFD)
	}
}

func normalizeRegistryPID(pid int) int {
	if pid < 0 {
		return 0
	}
	return pid
}

func (r *FDRegistry) lookupKeyLocked(pid int, childFD int) (fdRegistryKey, bool) {
	exactKey := fdRegistryKey{pid: pid, fd: childFD}
	if _, ok := r.states[exactKey]; ok {
		return exactKey, true
	}

	var (
		fallback fdRegistryKey
		found    bool
	)
	for key := range r.states {
		if key.fd != childFD {
			continue
		}
		if found {
			return fdRegistryKey{}, false
		}
		fallback = key
		found = true
	}
	if found {
		return fallback, true
	}
	return fdRegistryKey{}, false
}
