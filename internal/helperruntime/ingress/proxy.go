package ingress

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"

	"github.com/moolen/bbox/internal/helperproto"
	bridgepkg "github.com/moolen/bbox/internal/helperruntime/bridge"
)

type TunnelRelayResult struct {
	SendClose bool
	Write     bool
	Err       error
	Terminal  bool
}

type Bridge interface {
	ReadLoop(context.Context) error

	Logger() *log.Logger
	MITMEnabled() bool
	MaxRequestBodyBytes() int64

	ProxyRoundTrip(context.Context, helperproto.ProxyRequest) (*helperproto.ProxyResponse, error)
	Connect(context.Context, string, int) (uint64, <-chan helperproto.Envelope, *helperproto.ConnectResponse, error)
	AuthorizeConnect(context.Context, string, int) (*helperproto.ConnectResponse, error)
	RequestLeafCert(context.Context, string) (tls.Certificate, error)
	MITMRoundTrip(context.Context, helperproto.MITMRequest) (*helperproto.MITMResponse, error)

	RegisterTunnel(id uint64) <-chan helperproto.Envelope
	UnregisterTunnel(id uint64)
	DeliverTunnel(env helperproto.Envelope)
	SendTunnelClose(id uint64, write bool, tunnelErr error) error
	RelayPayloadToTunnel(conn net.Conn, id uint64, bufferedPayload []byte) TunnelRelayResult
	RelayTunnelToPayload(context.Context, net.Conn, <-chan helperproto.Envelope) TunnelRelayResult
}

func ProxyHandler(rt Bridge) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodConnect {
			if rt.MITMEnabled() {
				HandleMITMConnect(rt, w, req)
				return
			}
			HandleConnect(rt, w, req)
			return
		}

		serveHTTPForward(w, req, rt, RewriteProxyRequest)
	})
}

func serveHTTPForward(w http.ResponseWriter, req *http.Request, rt Bridge, rewrite func(*http.Request) (*http.Request, error)) {
	outReq, err := rewrite(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var body []byte
	if outReq.Body != nil {
		var tooLarge bool
		body, tooLarge, err = bridgepkg.ReadBoundedBody(outReq.Body, rt.MaxRequestBodyBytes())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if tooLarge {
			http.Error(w, "request body exceeds inspection limit", http.StatusRequestEntityTooLarge)
			return
		}
	}

	response, err := rt.ProxyRoundTrip(req.Context(), helperproto.ProxyRequest{
		Method: outReq.Method,
		URL:    outReq.URL.String(),
		Header: outReq.Header.Clone(),
		Body:   body,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	copyHeader(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	if _, err := io.Copy(w, bytes.NewReader(response.Body)); err != nil {
		bridgeLogger(rt).Printf("copy proxied response body: %v", err)
	}
}

func RewriteProxyRequest(req *http.Request) (*http.Request, error) {
	if req.URL == nil || req.URL.Scheme == "" || req.URL.Host == "" {
		return nil, errors.New("proxy request must use an absolute URL")
	}

	out := req.Clone(req.Context())
	urlCopy := *req.URL
	out.URL = &urlCopy
	out.RequestURI = ""
	out.Host = out.URL.Host
	out.Header = req.Header.Clone()
	out.Header.Del("Proxy-Connection")

	return out, nil
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func bridgeLogger(rt Bridge) *log.Logger {
	if logger := rt.Logger(); logger != nil {
		return logger
	}
	return log.New(io.Discard, "", 0)
}
