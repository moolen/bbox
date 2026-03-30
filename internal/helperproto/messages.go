package helperproto

import "net/http"

const ProtocolVersion = 9

type Envelope struct {
	ID               uint64
	Hello            *Hello
	Ready            *Ready
	ProxyRequest     *ProxyRequest
	ProxyResponse    *ProxyResponse
	ConnectRequest   *ConnectRequest
	ConnectResponse  *ConnectResponse
	DNSRequest       *DNSRequest
	DNSResponse      *DNSResponse
	LeafCertRequest  *LeafCertRequest
	LeafCertResponse *LeafCertResponse
	MITMRequest      *MITMRequest
	MITMResponse     *MITMResponse
	TunnelFrame      *TunnelFrame
	TunnelClose      *TunnelClose
	ExecRequest      *ExecRequest
	ExecInput        *ExecInput
	StreamFrame      *StreamFrame
	ExecResult       *ExecResult
}

func (e Envelope) Kind() string {
	switch {
	case e.Hello != nil:
		return "hello"
	case e.Ready != nil:
		return "ready"
	case e.ProxyRequest != nil:
		return "proxy_request"
	case e.ProxyResponse != nil:
		return "proxy_response"
	case e.ConnectRequest != nil:
		return "connect_request"
	case e.ConnectResponse != nil:
		return "connect_response"
	case e.DNSRequest != nil:
		return "dns_request"
	case e.DNSResponse != nil:
		return "dns_response"
	case e.LeafCertRequest != nil:
		return "leaf_cert_request"
	case e.LeafCertResponse != nil:
		return "leaf_cert_response"
	case e.MITMRequest != nil:
		return "mitm_request"
	case e.MITMResponse != nil:
		return "mitm_response"
	case e.TunnelFrame != nil:
		return "tunnel_frame"
	case e.TunnelClose != nil:
		return "tunnel_close"
	case e.ExecRequest != nil:
		return "exec_request"
	case e.ExecInput != nil:
		return "exec_input"
	case e.StreamFrame != nil:
		return "stream_frame"
	case e.ExecResult != nil:
		return "exec_result"
	default:
		return "unknown"
	}
}

type Hello struct {
	ProtocolVersion int
	SandboxID       string
}

type Ready struct {
	ProtocolVersion int
	ProxyAddr       string
	DNSAddr         string
	TCPAddr         string
}

type ProxyRequest struct {
	Method string
	URL    string
	Header http.Header
	Body   []byte
}

type ProxyResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	Error      string
}

type ConnectRequest struct {
	Host        string
	Port        int
	Transparent bool
}

type ConnectResponse struct {
	StatusCode int
	Message    string
	Error      string
}

type DNSRequest struct {
	Network string
	Host    string
	Port    int
	Payload []byte
}

type DNSResponse struct {
	Payload []byte
	Error   string
}

type LeafCertRequest struct {
	Host string
}

type LeafCertResponse struct {
	CertPEM []byte
	KeyPEM  []byte
	Error   string
}

type MITMRequest struct {
	Scheme       string
	Authority    string
	Host         string
	Method       string
	Path         string
	RawQuery     string
	Header       http.Header
	Body         []byte
	Proto        string
	BodyTooLarge bool
}

type MITMResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	Error      string
}

type TunnelFrame struct {
	Data []byte
}

type TunnelClose struct {
	Write bool
	Error string
}

type ExecRequest struct {
	Argv        []string
	Env         []string
	WorkDir     string
	Interactive bool
	Terminal    bool
	InitialSize *TerminalSize
}

type TerminalSize struct {
	Rows uint16
	Cols uint16
}

type ExecInput struct {
	Data   []byte
	EOF    bool
	Resize *TerminalSize
	Cancel bool
}

type StreamType string

const (
	StreamStdout StreamType = "stdout"
	StreamStderr StreamType = "stderr"
)

type StreamFrame struct {
	Stream StreamType
	Data   []byte
}

type ExecResult struct {
	ExitCode int
	Stderr   []byte
	Error    string
}
