package ingress

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/moolen/bbox/internal/helperproto"
)

const delayedTransparentHandshakeFragment = 350 * time.Millisecond

func TestServeTransparentTCPConnAcceptsFragmentedHTTP1Request(t *testing.T) {
	rt := &stubTransparentBridge{
		authorizeCh: make(chan struct{}, 1),
		proxyCh:     make(chan struct{}, 1),
	}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		ServeTransparentTCPConn(serverConn, rt, "registry.npmjs.org", 80)
	}()

	if _, err := io.WriteString(clientConn, "G"); err != nil {
		t.Fatalf("write first fragment: %v", err)
	}
	time.Sleep(delayedTransparentHandshakeFragment)
	if _, err := io.WriteString(clientConn, "ET / HTTP/1.1\r\nHost: registry.npmjs.org\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write second fragment: %v", err)
	}

	awaitSignal(t, rt.authorizeCh, "transparent HTTP authorize")
	awaitSignal(t, rt.proxyCh, "transparent HTTP proxy round trip")
	_ = clientConn.Close()
	<-done
}

func TestServeTransparentTCPConnAcceptsFragmentedTLSClientHelloPrefix(t *testing.T) {
	rt := &stubTransparentBridge{
		mitmEnabled: false,
		authorizeCh: make(chan struct{}, 1),
	}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		ServeTransparentTCPConn(serverConn, rt, "repo.maven.apache.org", 443)
	}()

	if _, err := clientConn.Write([]byte{0x16}); err != nil {
		t.Fatalf("write first TLS fragment: %v", err)
	}
	time.Sleep(delayedTransparentHandshakeFragment)
	if _, err := clientConn.Write([]byte{0x03, 0x03}); err != nil {
		t.Fatalf("write second TLS fragment: %v", err)
	}

	awaitSignal(t, rt.authorizeCh, "transparent TLS authorize")
	_ = clientConn.Close()
	<-done
}

func awaitSignal(t *testing.T, ch <-chan struct{}, label string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", label)
	}
}

type stubTransparentBridge struct {
	mitmEnabled bool
	authorizeCh chan struct{}
	proxyCh     chan struct{}
}

func (s *stubTransparentBridge) ReadLoop(context.Context) error { return nil }

func (s *stubTransparentBridge) Logger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

func (s *stubTransparentBridge) MITMEnabled() bool { return s.mitmEnabled }

func (s *stubTransparentBridge) MaxRequestBodyBytes() int64 { return 1 << 20 }

func (s *stubTransparentBridge) ProxyRoundTrip(context.Context, helperproto.ProxyRequest) (*helperproto.ProxyResponse, error) {
	if s.proxyCh != nil {
		s.proxyCh <- struct{}{}
	}
	return &helperproto.ProxyResponse{StatusCode: http.StatusNoContent, Header: http.Header{}}, nil
}

func (s *stubTransparentBridge) Connect(context.Context, string, int) (uint64, <-chan helperproto.Envelope, *helperproto.ConnectResponse, error) {
	return 0, nil, nil, errors.New("unexpected Connect call")
}

func (s *stubTransparentBridge) AuthorizeConnect(context.Context, string, int) (*helperproto.ConnectResponse, error) {
	return nil, errors.New("unexpected AuthorizeConnect call")
}

func (s *stubTransparentBridge) AuthorizeTransparentConnect(context.Context, string, int) (*helperproto.ConnectResponse, error) {
	if s.authorizeCh != nil {
		s.authorizeCh <- struct{}{}
	}
	return &helperproto.ConnectResponse{StatusCode: http.StatusOK}, nil
}

func (s *stubTransparentBridge) RequestLeafCert(context.Context, string) (tls.Certificate, error) {
	return tls.Certificate{}, errors.New("unexpected RequestLeafCert call")
}

func (s *stubTransparentBridge) MITMRoundTrip(context.Context, helperproto.MITMRequest) (*helperproto.MITMResponse, error) {
	return nil, errors.New("unexpected MITMRoundTrip call")
}

func (s *stubTransparentBridge) RegisterTunnel(uint64) <-chan helperproto.Envelope { return nil }

func (s *stubTransparentBridge) UnregisterTunnel(uint64) {}

func (s *stubTransparentBridge) DeliverTunnel(helperproto.Envelope) {}

func (s *stubTransparentBridge) SendTunnelClose(uint64, bool, error) error { return nil }

func (s *stubTransparentBridge) RelayPayloadToTunnel(net.Conn, uint64, []byte) TunnelRelayResult {
	return TunnelRelayResult{}
}

func (s *stubTransparentBridge) RelayTunnelToPayload(context.Context, net.Conn, <-chan helperproto.Envelope) TunnelRelayResult {
	return TunnelRelayResult{}
}
