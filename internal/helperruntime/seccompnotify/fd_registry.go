package seccompnotify

import (
	"sync"

	"golang.org/x/sys/unix"
)

const minManagedHelperFD = 3

type FDRegistry struct {
	mu     sync.RWMutex
	states map[int]SocketState
}

func NewFDRegistry() *FDRegistry {
	return &FDRegistry{
		states: make(map[int]SocketState),
	}
}

func (r *FDRegistry) Insert(state SocketState) {
	if r == nil || state.ChildFD < 0 {
		return
	}

	r.mu.Lock()
	r.states[state.ChildFD] = state
	r.mu.Unlock()
}

func (r *FDRegistry) Lookup(childFD int) (SocketState, bool) {
	if r == nil || childFD < 0 {
		return SocketState{}, false
	}

	r.mu.RLock()
	state, ok := r.states[childFD]
	r.mu.RUnlock()
	return state, ok
}

func (r *FDRegistry) Dup(sourceFD, targetFD int) error {
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

	state, ok := r.states[sourceFD]
	if !ok {
		return unix.EBADF
	}

	duplicated := state
	duplicated.ChildFD = targetFD
	if state.HelperFD >= minManagedHelperFD {
		helperFD, err := unix.Dup(state.HelperFD)
		if err != nil {
			return err
		}
		duplicated.HelperFD = helperFD
	}

	if existing, ok := r.states[targetFD]; ok {
		// Avoid closing the source helper fd when state was manually copied.
		if existing.HelperFD != state.HelperFD {
			closeManagedHelperFD(existing.HelperFD)
		}
	}
	r.states[targetFD] = duplicated
	return nil
}

func (r *FDRegistry) Close(childFD int) {
	if r == nil || childFD < 0 {
		return
	}

	r.mu.Lock()
	if state, ok := r.states[childFD]; ok {
		closeManagedHelperFD(state.HelperFD)
	}
	delete(r.states, childFD)
	r.mu.Unlock()
}

func closeManagedHelperFD(helperFD int) {
	if helperFD >= minManagedHelperFD {
		_ = unix.Close(helperFD)
	}
}
