package bbox

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moolen/bbox/internal/helperproto"
)

func TestHelperClientRunSendFailureDoesNotWedgeFutureRuns(t *testing.T) {
	client := newHelperClient(nil, "sandbox-a", failingConn{writeErr: errors.New("write failed")})

	_, err := client.Run(context.Background(), []string{"/bin/echo", "first"}, RunOptions{})
	if err == nil || !strings.Contains(err.Error(), "send exec request") {
		t.Fatalf("expected send failure, got %v", err)
	}

	_, err = client.Run(context.Background(), []string{"/bin/echo", "second"}, RunOptions{})
	if err == nil {
		t.Fatal("expected second run to fail")
	}
	if strings.Contains(err.Error(), "already running") {
		t.Fatalf("expected client to clear busy state after send failure, got %v", err)
	}
}

func TestHelperClientRunPropagatesExecResultError(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	client := newHelperClient(nil, "sandbox-a", clientSide)

	go func() {
		client.loopDone <- client.readLoop()
	}()

	serverErrCh := make(chan error, 1)
	go func() {
		dec := gob.NewDecoder(serverSide)
		enc := gob.NewEncoder(serverSide)

		var req helperproto.Envelope
		if err := dec.Decode(&req); err != nil {
			serverErrCh <- err
			return
		}
		if req.ExecRequest == nil {
			serverErrCh <- errors.New("expected exec request")
			return
		}

		serverErrCh <- enc.Encode(&helperproto.Envelope{
			ID: req.ID,
			ExecResult: &helperproto.ExecResult{
				ExitCode: -1,
				Stderr:   []byte("stderr text"),
				Error:    "exec failed",
			},
		})
	}()

	result, err := client.Run(context.Background(), []string{"/bin/echo", "hello"}, RunOptions{})
	if err == nil || !strings.Contains(err.Error(), "exec failed") {
		t.Fatalf("expected exec result error to be returned, got %v", err)
	}
	if result == nil {
		t.Fatal("expected run result to be returned alongside the error")
	}
	if result.ExitCode != -1 {
		t.Fatalf("unexpected exit code: got %d", result.ExitCode)
	}
	if got := string(result.Stderr); got != "stderr text" {
		t.Fatalf("unexpected stderr: got %q", got)
	}

	if err := <-serverErrCh; err != nil {
		t.Fatalf("server side failed: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}
	if err := serverSide.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("close server side: %v", err)
	}
}

func TestHelperClientInteractiveRunStreamsOutput(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	client := newHelperClient(nil, "sandbox-a", clientSide)
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = serverSide.Close() })

	go func() {
		client.loopDone <- client.readLoop()
	}()

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	serverErrCh := make(chan error, 1)
	go func() {
		dec := gob.NewDecoder(serverSide)
		enc := gob.NewEncoder(serverSide)

		var req helperproto.Envelope
		if err := dec.Decode(&req); err != nil {
			serverErrCh <- err
			return
		}
		if req.ExecRequest == nil {
			serverErrCh <- errors.New("expected exec request")
			return
		}
		if !req.ExecRequest.Interactive {
			serverErrCh <- errors.New("expected interactive exec request")
			return
		}

		var input helperproto.Envelope
		if err := dec.Decode(&input); err != nil {
			serverErrCh <- err
			return
		}
		if input.ExecInput == nil {
			serverErrCh <- errors.New("expected exec input envelope")
			return
		}
		if got := string(input.ExecInput.Data); got != "ping\n" {
			serverErrCh <- errors.New("unexpected stdin frame payload: " + got)
			return
		}

		if err := enc.Encode(&helperproto.Envelope{
			ID: req.ID,
			StreamFrame: &helperproto.StreamFrame{
				Stream: helperproto.StreamStdout,
				Data:   []byte("hello stdout\n"),
			},
		}); err != nil {
			serverErrCh <- err
			return
		}
		if err := enc.Encode(&helperproto.Envelope{
			ID: req.ID,
			StreamFrame: &helperproto.StreamFrame{
				Stream: helperproto.StreamStderr,
				Data:   []byte("hello stderr\n"),
			},
		}); err != nil {
			serverErrCh <- err
			return
		}
		serverErrCh <- enc.Encode(&helperproto.Envelope{
			ID: req.ID,
			ExecResult: &helperproto.ExecResult{
				ExitCode: 0,
			},
		})
	}()

	result, err := client.Run(context.Background(), []string{"/bin/sh"}, RunOptions{
		Interactive: true,
		Stdin:       strings.NewReader("ping\n"),
		Stdout:      &stdout,
		Stderr:      &stderr,
	})
	if err != nil {
		t.Fatalf("expected interactive run to succeed, got %v", err)
	}
	if result == nil {
		t.Fatal("expected run result")
	}
	if result.ExitCode != 0 {
		t.Fatalf("unexpected exit code: got %d", result.ExitCode)
	}
	if got := stdout.String(); got != "hello stdout\n" {
		t.Fatalf("unexpected streamed stdout: got %q", got)
	}
	if got := stderr.String(); got != "hello stderr\n" {
		t.Fatalf("unexpected streamed stderr: got %q", got)
	}

	if err := <-serverErrCh; err != nil {
		t.Fatalf("server side failed: %v", err)
	}
}

func TestHelperClientStartAcceptsTransparentReadyEnvelope(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	client := newHelperClient(nil, "sandbox-a", clientSide)
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = serverSide.Close() })

	serverErrCh := make(chan error, 1)
	go func() {
		dec := gob.NewDecoder(serverSide)
		enc := gob.NewEncoder(serverSide)

		var hello helperproto.Envelope
		if err := dec.Decode(&hello); err != nil {
			serverErrCh <- err
			return
		}
		if hello.Hello == nil {
			serverErrCh <- errors.New("expected hello envelope")
			return
		}

		serverErrCh <- enc.Encode(&helperproto.Envelope{
			ID: hello.ID,
			Ready: &helperproto.Ready{
				ProtocolVersion: helperproto.ProtocolVersion,
				DNSAddr:         "127.0.0.1:53",
				HTTPAddr:        "127.0.0.1:80",
				HTTPSAddr:       "127.0.0.1:443",
			},
		})
	}()

	proxyAddr, err := client.Start(context.Background())
	if err != nil {
		t.Fatalf("expected transparent readiness to succeed, got %v", err)
	}
	if proxyAddr != "" {
		t.Fatalf("expected no proxy address for transparent readiness, got %q", proxyAddr)
	}

	if err := <-serverErrCh; err != nil {
		t.Fatalf("server side failed: %v", err)
	}
}

func TestHelperClientTunnelActivationIsIdempotent(t *testing.T) {
	client := newHelperClient(nil, "sandbox-a", failingConn{writeErr: io.EOF})
	tunnel := &hostTunnel{}
	client.registerPendingTunnel(7, tunnel)
	if !client.activateTunnel(7) {
		t.Fatal("first activation should succeed")
	}
	if client.activateTunnel(7) {
		t.Fatal("second activation should fail")
	}
}

type failingConn struct {
	writeErr error
}

func (c failingConn) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (c failingConn) Write([]byte) (int, error) {
	return 0, c.writeErr
}

func (c failingConn) Close() error {
	return nil
}

func mustCompilePolicy(t *testing.T, policy NetworkPolicy) *compiledPolicy {
	t.Helper()

	compiled, err := compilePolicy(policy)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return compiled
}

func TestHelperClientHandlesConnectRequest(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	t.Cleanup(func() { _ = serverSide.Close() })

	prevDialTunnel := dialTunnelFn
	dialTunnelFn = func(ctx context.Context, host string, port int) (net.Conn, error) {
		local, remote := net.Pipe()
		_ = remote.Close()
		return local, nil
	}
	t.Cleanup(func() { dialTunnelFn = prevDialTunnel })

	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{
		AllowHostPatterns: []string{`^example[.]com$`},
		AllowConnect:      true,
		AllowConnectPorts: []string{"443"},
	}))
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	client := newHelperClient(manager, "sandbox-a", clientSide)
	t.Cleanup(func() { _ = client.Close() })

	go func() {
		client.loopDone <- client.readLoop()
	}()

	enc := gob.NewEncoder(serverSide)
	dec := gob.NewDecoder(serverSide)
	if err := enc.Encode(&helperproto.Envelope{
		ID: 3,
		ConnectRequest: &helperproto.ConnectRequest{
			Host: "example.com",
			Port: 443,
		},
	}); err != nil {
		t.Fatal(err)
	}

	_ = serverSide.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	var got helperproto.Envelope
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	_ = serverSide.SetReadDeadline(time.Time{})
	if got.ConnectResponse == nil || got.ConnectResponse.StatusCode != http.StatusOK {
		t.Fatalf("unexpected connect response: %#v", got.ConnectResponse)
	}
}

func TestHostTunnelDoesNotShutdownOnOutboundEOF(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	t.Cleanup(func() { _ = serverSide.Close() })

	outbound := &recordingEOFConn{}

	prevDialTunnel := dialTunnelFn
	dialTunnelFn = func(ctx context.Context, host string, port int) (net.Conn, error) {
		return outbound, nil
	}
	t.Cleanup(func() { dialTunnelFn = prevDialTunnel })

	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{
		AllowHostPatterns: []string{`^example[.]com$`},
		AllowConnect:      true,
		AllowConnectPorts: []string{"443"},
	}))
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	client := newHelperClient(manager, "sandbox-a", clientSide)
	t.Cleanup(func() { _ = client.Close() })

	go func() {
		client.loopDone <- client.readLoop()
	}()

	enc := gob.NewEncoder(serverSide)
	dec := gob.NewDecoder(serverSide)

	if err := enc.Encode(&helperproto.Envelope{
		ID: 7,
		ConnectRequest: &helperproto.ConnectRequest{
			Host: "example.com",
			Port: 443,
		},
	}); err != nil {
		t.Fatal(err)
	}

	_ = serverSide.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	var got helperproto.Envelope
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ConnectResponse == nil || got.ConnectResponse.StatusCode != http.StatusOK {
		t.Fatalf("unexpected connect response: %#v", got.ConnectResponse)
	}

	// Outbound read side immediately hits EOF; the host should only half-close the tunnel
	// back to the helper and must keep accepting helper->outbound tunnel frames.
	_ = serverSide.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	var closeEnv helperproto.Envelope
	if err := dec.Decode(&closeEnv); err != nil {
		t.Fatal(err)
	}
	if closeEnv.TunnelClose == nil || !closeEnv.TunnelClose.Write {
		t.Fatalf("expected outbound EOF to send TunnelClose{Write:true}, got %#v", closeEnv)
	}

	// The host must not treat an outbound EOF as terminal: it should keep the outbound
	// socket open so helper->outbound writes can continue (half-close semantics).
	pollDeadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(pollDeadline) {
		if outbound.IsClosed() {
			t.Fatalf("outbound connection was closed after EOF; expected tunnel to remain writable")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if err := enc.Encode(&helperproto.Envelope{
		ID: 7,
		TunnelFrame: &helperproto.TunnelFrame{
			Data: []byte("ping"),
		},
	}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := outbound.String(); got == "ping" {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("expected tunnel frame to be written to outbound even after EOF; got %q", outbound.String())
}

func TestHostTunnelIgnoresReadDeadlineTimeouts(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	t.Cleanup(func() { _ = serverSide.Close() })

	client := newHelperClient(nil, "sandbox-a", clientSide)
	t.Cleanup(func() { _ = client.Close() })

	tunnel := newHostTunnel(client, 9, &timeoutThenEOFConn{})
	t.Cleanup(tunnel.shutdown)
	tunnel.start()

	dec := gob.NewDecoder(serverSide)
	_ = serverSide.SetReadDeadline(time.Now().Add(250 * time.Millisecond))

	var env helperproto.Envelope
	if err := dec.Decode(&env); err != nil {
		t.Fatal(err)
	}
	if env.TunnelClose == nil || !env.TunnelClose.Write {
		t.Fatalf("expected timeout to be ignored and eventual EOF to half-close, got %#v", env)
	}
	if env.TunnelClose.Error != "" {
		t.Fatalf("expected no timeout error to be propagated, got %q", env.TunnelClose.Error)
	}
}

func TestHelperClientBuffersTunnelFramesUntilTunnelActivation(t *testing.T) {
	outbound := &recordingEOFConn{}

	prevDialTunnel := dialTunnelFn
	dialTunnelFn = func(ctx context.Context, host string, port int) (net.Conn, error) {
		return outbound, nil
	}
	t.Cleanup(func() { dialTunnelFn = prevDialTunnel })

	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{
		AllowHostPatterns: []string{`^example[.]com$`},
		AllowConnect:      true,
		AllowConnectPorts: []string{"443"},
	}))
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	var client *helperClient
	conn := &writeHookConn{
		hook: func() {
			client.handleTunnelFrame(11, helperproto.TunnelFrame{Data: []byte("ping")})
		},
	}
	client = newHelperClient(manager, "sandbox-a", conn)
	t.Cleanup(func() {
		client.shutdownTunnels()
		_ = client.Close()
	})

	client.handleConnectRequest(11, helperproto.ConnectRequest{
		Host: "example.com",
		Port: 443,
	})

	deadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := outbound.String(); got == "ping" {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("expected frame queued during connect response send to reach outbound socket, got %q", outbound.String())
}

func TestHelperClientCloseCancelsInFlightConnectRequest(t *testing.T) {
	connectCanceled := make(chan struct{}, 1)

	prevDialTunnel := dialTunnelFn
	dialTunnelFn = func(ctx context.Context, host string, port int) (net.Conn, error) {
		<-ctx.Done()
		connectCanceled <- struct{}{}
		return nil, ctx.Err()
	}
	t.Cleanup(func() { dialTunnelFn = prevDialTunnel })

	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{
		AllowHostPatterns: []string{`^example[.]com$`},
		AllowConnect:      true,
		AllowConnectPorts: []string{"443"},
	}))
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	client := newHelperClient(manager, "sandbox-a", failingConn{writeErr: errors.New("write failed")})
	go client.handleConnectRequest(13, helperproto.ConnectRequest{Host: "example.com", Port: 443})

	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}

	select {
	case <-connectCanceled:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for connect dial context cancellation")
	}
}

func TestHelperClientCloseCancelsLifetimeContext(t *testing.T) {
	client := newHelperClient(nil, "sandbox-a", failingConn{writeErr: errors.New("write failed")})

	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}

	select {
	case <-client.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for helper client lifetime context cancellation")
	}
}

type recordingEOFConn struct {
	mu     sync.Mutex
	closed bool
	writes bytes.Buffer
}

func (c *recordingEOFConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *recordingEOFConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	return c.writes.Write(p)
}

func (c *recordingEOFConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *recordingEOFConn) LocalAddr() net.Addr  { return dummyAddr("local") }
func (c *recordingEOFConn) RemoteAddr() net.Addr { return dummyAddr("remote") }

func (c *recordingEOFConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingEOFConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingEOFConn) SetWriteDeadline(time.Time) error { return nil }

func (c *recordingEOFConn) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes.String()
}

func (c *recordingEOFConn) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

type timeoutThenEOFConn struct {
	mu     sync.Mutex
	reads  int
	closed bool
}

func (c *timeoutThenEOFConn) Read([]byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	c.reads++
	if c.reads == 1 {
		return 0, timeoutError{}
	}
	return 0, io.EOF
}

func (c *timeoutThenEOFConn) Write(p []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	return len(p), nil
}

func (c *timeoutThenEOFConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *timeoutThenEOFConn) LocalAddr() net.Addr  { return dummyAddr("local") }
func (c *timeoutThenEOFConn) RemoteAddr() net.Addr { return dummyAddr("remote") }

func (c *timeoutThenEOFConn) SetDeadline(time.Time) error      { return nil }
func (c *timeoutThenEOFConn) SetReadDeadline(time.Time) error  { return nil }
func (c *timeoutThenEOFConn) SetWriteDeadline(time.Time) error { return nil }

type writeHookConn struct {
	hook     func()
	hookOnce sync.Once
}

func (c *writeHookConn) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (c *writeHookConn) Write(p []byte) (int, error) {
	c.hookOnce.Do(func() {
		if c.hook != nil {
			c.hook()
		}
	})
	return len(p), nil
}

func (c *writeHookConn) Close() error {
	return nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }
