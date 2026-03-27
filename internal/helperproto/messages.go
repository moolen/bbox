package helperproto

import "net/http"

const ProtocolVersion = 1

type Envelope struct {
	ID            uint64
	Hello         *Hello
	Ready         *Ready
	ProxyRequest  *ProxyRequest
	ProxyResponse *ProxyResponse
	ExecRequest   *ExecRequest
	StreamFrame   *StreamFrame
	ExecResult    *ExecResult
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
	case e.ExecRequest != nil:
		return "exec_request"
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

type ExecRequest struct {
	Argv    []string
	Env     []string
	WorkDir string
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
