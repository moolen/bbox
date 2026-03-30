package seccompnotify

import "os"

type SocketKind string

const (
	KindUnknown SocketKind = "unknown"
	KindTCP     SocketKind = "tcp"
	KindUDP     SocketKind = "udp"
)

type SocketState struct {
	Kind         SocketKind
	ChildFD      int
	HelperFD     int
	Family       int
	SocketType   int
	Protocol     int
	Blocking     bool
	DNSManaged   bool
	OriginalHost string
	OriginalPort int
	RedirectAddr string
}

type RuntimeTargets struct {
	DNSAddr            string
	HTTPAddr           string
	HTTPAddrV6         string
	HTTPSAddr          string
	HTTPSAddrV6        string
	RawTCPAddr         string
	RawTCPAddrV6       string
	RecordRawTCPOrigin func(localAddr, host string, port int)
}

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

type Supervisor struct {
	targets       RuntimeTargets
	registry      *FDRegistry
	notifySock    *os.File
	notifyChild   *os.File
	notifyFD      int
	launcherError error
}

func NewSupervisor(targets RuntimeTargets) (*Supervisor, error) {
	return &Supervisor{
		targets:  targets,
		registry: NewFDRegistry(),
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
