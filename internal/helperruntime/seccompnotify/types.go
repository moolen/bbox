package seccompnotify

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
)

type SocketKind string

const (
	KindUnknown SocketKind = "unknown"
	KindTCP     SocketKind = "tcp"
	KindUDP     SocketKind = "udp"
)

type SocketState struct {
	// Kind selects the syscall emulation path for this child FD.
	Kind       SocketKind
	ChildPID   int
	ChildFD    int
	HelperFD   int
	Family     int
	SocketType int
	Protocol   int
	Blocking   bool
	// DNSManaged marks UDP sockets that have been switched from kernel I/O to
	// helper-mediated DNS request/response emulation.
	DNSManaged    bool
	ConnectedHost string
	ConnectedPort int
	// PendingDNSResponses buffers helper replies until the child issues a
	// matching recv*/poll syscall.
	PendingDNSResponses []dnsPacketResponse
	// OriginalHost/OriginalPort retain the destination that triggered a raw TCP
	// redirect so the transparent ingress can recover policy context.
	OriginalHost string
	OriginalPort int
	// RedirectAddr records the helper-side endpoint that the child socket was
	// actually connected to after seccomp redirection.
	RedirectAddr string
}

type dnsPacketResponse struct {
	Payload []byte
	Source  DecodedSockaddr
}

// RuntimeTargets describes the helper endpoints and callbacks that seccomp
// socket emulation can hand traffic to.
type RuntimeTargets struct {
	DNSRoundTrip          func(ctx context.Context, network, host string, port int, payload []byte) ([]byte, error)
	RawTCPAddr            string
	RawTCPAddrV6          string
	RecordRawTCPOrigin    func(localAddr, host string, port int)
	PayloadSeccompBPFPath string
}

// DecodedSockaddr is the normalized form used after copying a sockaddr out of
// the sandboxed process.
type DecodedSockaddr struct {
	Family int
	Host   string
	Port   int
}

type syscallData struct {
	Syscall int
}

type syscallRequest struct {
	Data        syscallData
	Socket      socketRequest
	Connect     connectRequest
	Close       closeRequest
	Dup         dupRequest
	Getpeername getpeernameRequest
}

type socketRequest struct {
	ChildFD    int
	Family     int
	SocketType int
	Protocol   int
}

type connectRequest struct {
	ChildFD     int
	Destination DecodedSockaddr
}

type closeRequest struct {
	ChildFD int
}

type dupRequest struct {
	FD    int
	OldFD int
	NewFD int
	Cmd   int
	Arg   int
}

type getpeernameRequest struct {
	ChildFD       int
	WritePeername func(DecodedSockaddr) error
}

// Supervisor owns the seccomp notify control channel and the per-FD state used
// to emulate socket syscalls on behalf of the sandboxed process.
type Supervisor struct {
	targets               RuntimeTargets
	registry              *FDRegistry
	notifySock            *os.File
	notifyChild           *os.File
	notifyReceiveFD       int
	notifyFD              int
	notifyServeWG         sync.WaitGroup
	notifyFDIOMu          sync.Mutex
	childFDMu             sync.Mutex
	reservedChildFDs      map[int]struct{}
	nextTCPChildFD        int
	nextUDPChildFD        int
	notifyQueueMu         sync.Mutex
	notifyQueueTails      map[fdRegistryKey]chan struct{}
	notifyQueueRefs       map[fdRegistryKey]int
	launcherErrorMu       sync.Mutex
	launcherError         error
	launcherClose         func() error
	payloadSeccompBPFPath string
	closing               atomic.Bool
}

func NewSupervisor(targets RuntimeTargets) (*Supervisor, error) {
	return &Supervisor{
		targets:          targets,
		registry:         NewFDRegistry(),
		reservedChildFDs: make(map[int]struct{}),
		nextTCPChildFD:   minManagedTCPChildFD,
		nextUDPChildFD:   minManagedUDPChildFD,
		notifyQueueTails: make(map[fdRegistryKey]chan struct{}),
		notifyQueueRefs:  make(map[fdRegistryKey]int),
	}, nil
}

func (s *Supervisor) Registry() *FDRegistry {
	if s == nil {
		return nil
	}
	return s.registry
}

func (s *Supervisor) Targets() RuntimeTargets {
	if s == nil {
		return RuntimeTargets{}
	}
	return s.targets
}

func (s *Supervisor) SetPayloadSeccompBPFPath(path string) {
	if s == nil {
		return
	}
	s.payloadSeccompBPFPath = path
}
