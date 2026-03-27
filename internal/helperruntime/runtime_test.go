package helperruntime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/moolen/bbox/internal/helperproto"
)

func TestReadLoopRespondsToHelloWithReady(t *testing.T) {
	bridge, peer, errCh := startReadLoop(t, "127.0.0.1:31111")
	defer bridge.Close()
	defer peer.Close()

	enc := gob.NewEncoder(peer)
	dec := gob.NewDecoder(peer)

	if err := enc.Encode(&helperproto.Envelope{
		ID: 17,
		Hello: &helperproto.Hello{
			ProtocolVersion: helperproto.ProtocolVersion,
			SandboxID:       "sandbox-a",
		},
	}); err != nil {
		t.Fatal(err)
	}

	var got helperproto.Envelope
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}

	if got.ID != 17 {
		t.Fatalf("unexpected response ID: got %d", got.ID)
	}
	if got.Ready == nil {
		t.Fatalf("expected ready response, got %#v", got)
	}
	if got.Ready.ProtocolVersion != helperproto.ProtocolVersion {
		t.Fatalf("unexpected protocol version: got %d", got.Ready.ProtocolVersion)
	}
	if got.Ready.ProxyAddr != "127.0.0.1:31111" {
		t.Fatalf("unexpected proxy address: got %q", got.Ready.ProxyAddr)
	}

	closeReadLoop(t, peer, errCh)
}

func TestReadLoopRejectsHelloWithUnexpectedProtocolVersion(t *testing.T) {
	bridge, peer, errCh := startReadLoop(t, "127.0.0.1:31111")
	defer bridge.Close()
	defer peer.Close()

	enc := gob.NewEncoder(peer)
	if err := enc.Encode(&helperproto.Envelope{
		ID: 1,
		Hello: &helperproto.Hello{
			ProtocolVersion: helperproto.ProtocolVersion + 1,
		},
	}); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "unsupported protocol version") {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("expected protocol version mismatch to stop the read loop")
	}
}

func TestReadLoopIgnoresUnknownEnvelopeKinds(t *testing.T) {
	bridge, peer, errCh := startReadLoop(t, "127.0.0.1:31111")
	defer bridge.Close()
	defer peer.Close()

	enc := gob.NewEncoder(peer)
	dec := gob.NewDecoder(peer)

	if err := enc.Encode(&helperproto.Envelope{ID: 5}); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("read loop exited after unknown envelope: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	if err := enc.Encode(&helperproto.Envelope{
		ID: 6,
		Hello: &helperproto.Hello{
			ProtocolVersion: helperproto.ProtocolVersion,
		},
	}); err != nil {
		t.Fatal(err)
	}

	var got helperproto.Envelope
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Ready == nil {
		t.Fatalf("expected ready response after unknown envelope, got %#v", got)
	}

	closeReadLoop(t, peer, errCh)
}

func TestProxyHandlerRejectsMalformedConnectTarget(t *testing.T) {
	bridgeSide, peerSide := net.Pipe()
	defer bridgeSide.Close()
	defer peerSide.Close()

	handler := newBridge(bridgeSide, log.New(io.Discard, "", 0), "127.0.0.1:31111").proxyHandler()

	req := httptest.NewRequest(http.MethodConnect, "http://proxy.invalid", nil)
	req.Host = "example.com"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
	if !strings.Contains(strings.ToLower(w.Body.String()), "malformed") {
		t.Fatalf("expected malformed target error, got %q", w.Body.String())
	}
}

func TestProxyHandlerConnectDenied(t *testing.T) {
	bridgeSide, peerSide := net.Pipe()
	defer bridgeSide.Close()
	defer peerSide.Close()

	bridge := newBridge(bridgeSide, log.New(io.Discard, "", 0), "127.0.0.1:31111")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readLoopErrCh := make(chan error, 1)
	go func() {
		readLoopErrCh <- bridge.readLoop(ctx)
	}()

	peerErrCh := make(chan error, 1)
	go func() {
		dec := gob.NewDecoder(peerSide)
		enc := gob.NewEncoder(peerSide)

		var req helperproto.Envelope
		if err := dec.Decode(&req); err != nil {
			peerErrCh <- err
			return
		}
		if req.ConnectRequest == nil {
			peerErrCh <- fmt.Errorf("expected connect request, got %#v", req)
			return
		}
		if req.ConnectRequest.Host != "example.com" || req.ConnectRequest.Port != 443 {
			peerErrCh <- fmt.Errorf("unexpected connect request payload: %#v", req.ConnectRequest)
			return
		}
		if err := enc.Encode(&helperproto.Envelope{
			ID: req.ID,
			ConnectResponse: &helperproto.ConnectResponse{
				StatusCode: http.StatusForbidden,
				Message:    "blocked by policy",
				Error:      "blocked by policy",
			},
		}); err != nil {
			peerErrCh <- err
			return
		}

		peerErrCh <- nil
	}()

	server := httptest.NewServer(bridge.proxyHandler())
	defer server.Close()

	addr := server.Listener.Addr().String()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected denied connect response, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "blocked by policy") {
		t.Fatalf("expected denial reason in body, got %q", string(body))
	}

	select {
	case err := <-peerErrCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for bridge peer to observe connect request")
	}

	cancel()
	if err := peerSide.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-readLoopErrCh:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected readLoop shutdown error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for readLoop to exit")
	}
}

func TestProxyHandlerConnectTimeoutMapsToGatewayTimeout(t *testing.T) {
	bridgeSide, peerSide := net.Pipe()
	defer bridgeSide.Close()
	defer peerSide.Close()

	bridge := newBridge(bridgeSide, log.New(io.Discard, "", 0), "127.0.0.1:31111")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readLoopErrCh := make(chan error, 1)
	go func() {
		readLoopErrCh <- bridge.readLoop(ctx)
	}()

	peerObservedReq := make(chan error, 1)
	go func() {
		dec := gob.NewDecoder(peerSide)
		var req helperproto.Envelope
		if err := dec.Decode(&req); err != nil {
			peerObservedReq <- err
			return
		}
		if req.ConnectRequest == nil {
			peerObservedReq <- fmt.Errorf("expected connect request, got %#v", req)
			return
		}
		peerObservedReq <- nil
	}()

	server := httptest.NewServer(bridge.proxyHandler())
	defer server.Close()

	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(7 * time.Second))

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("expected %d for timeout, got %d", http.StatusGatewayTimeout, resp.StatusCode)
	}

	select {
	case err := <-peerObservedReq:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for bridge peer to observe connect request")
	}

	cancel()
	if err := peerSide.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readLoopErrCh:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected readLoop shutdown error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for readLoop to exit")
	}
}

func TestProxyHandlerTunnelCloseWriteHalfClose(t *testing.T) {
	bridgeSide, peerSide := net.Pipe()
	defer bridgeSide.Close()
	defer peerSide.Close()

	bridge := newBridge(bridgeSide, log.New(io.Discard, "", 0), "127.0.0.1:31111")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readLoopErrCh := make(chan error, 1)
	go func() {
		readLoopErrCh <- bridge.readLoop(ctx)
	}()

	sendRemoteHalfClose := make(chan struct{})
	peerErrCh := make(chan error, 1)
	go func() {
		dec := gob.NewDecoder(peerSide)
		enc := gob.NewEncoder(peerSide)

		var req helperproto.Envelope
		if err := dec.Decode(&req); err != nil {
			peerErrCh <- err
			return
		}
		if req.ConnectRequest == nil {
			peerErrCh <- fmt.Errorf("expected connect request, got %#v", req)
			return
		}
		if err := enc.Encode(&helperproto.Envelope{
			ID: req.ID,
			ConnectResponse: &helperproto.ConnectResponse{
				StatusCode: http.StatusOK,
				Message:    "ok",
			},
		}); err != nil {
			peerErrCh <- err
			return
		}

		<-sendRemoteHalfClose
		if err := enc.Encode(&helperproto.Envelope{
			ID: req.ID,
			TunnelClose: &helperproto.TunnelClose{
				Write: true,
			},
		}); err != nil {
			peerErrCh <- err
			return
		}

		var frame helperproto.Envelope
		if err := dec.Decode(&frame); err != nil {
			peerErrCh <- err
			return
		}
		if frame.TunnelFrame == nil || string(frame.TunnelFrame.Data) != "ping" {
			peerErrCh <- fmt.Errorf("expected tunnel frame with ping, got %#v", frame)
			return
		}

		peerErrCh <- nil
	}()

	server := httptest.NewServer(bridge.proxyHandler())
	defer server.Close()

	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 connect response, got %d", resp.StatusCode)
	}

	close(sendRemoteHalfClose)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	_, err = conn.Read(one[:])
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after remote write-half-close, got %v", err)
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("expected write side to remain open, got %v", err)
	}

	select {
	case err := <-peerErrCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for tunnel frame after half-close")
	}

	cancel()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := peerSide.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readLoopErrCh:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected readLoop shutdown error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for readLoop to exit")
	}
}

func TestProxyHandlerConnectDeliversEarlyTunnelFrame(t *testing.T) {
	bridgeSide, peerSide := net.Pipe()
	defer bridgeSide.Close()
	defer peerSide.Close()

	bridge := newBridge(bridgeSide, log.New(io.Discard, "", 0), "127.0.0.1:31111")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readLoopErrCh := make(chan error, 1)
	go func() {
		readLoopErrCh <- bridge.readLoop(ctx)
	}()

	peerErrCh := make(chan error, 1)
	go func() {
		dec := gob.NewDecoder(peerSide)
		enc := gob.NewEncoder(peerSide)

		var req helperproto.Envelope
		if err := dec.Decode(&req); err != nil {
			peerErrCh <- err
			return
		}
		if req.ConnectRequest == nil {
			peerErrCh <- fmt.Errorf("expected connect request, got %#v", req)
			return
		}
		if err := enc.Encode(&helperproto.Envelope{
			ID: req.ID,
			ConnectResponse: &helperproto.ConnectResponse{
				StatusCode: http.StatusOK,
				Message:    "ok",
			},
		}); err != nil {
			peerErrCh <- err
			return
		}
		if err := enc.Encode(&helperproto.Envelope{
			ID: req.ID,
			TunnelFrame: &helperproto.TunnelFrame{
				Data: []byte("early"),
			},
		}); err != nil {
			peerErrCh <- err
			return
		}

		peerErrCh <- nil
	}()

	server := httptest.NewServer(bridge.proxyHandler())
	defer server.Close()

	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected connect 200, got %d", resp.StatusCode)
	}

	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, len("early"))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "early" {
		t.Fatalf("unexpected early tunnel payload: %q", string(got))
	}

	select {
	case err := <-peerErrCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for bridge peer")
	}

	cancel()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := peerSide.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readLoopErrCh:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected readLoop shutdown error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for readLoop to exit")
	}
}

func TestProxyHandlerConnectRelaysHijackerBufferedPayload(t *testing.T) {
	bridgeSide, peerSide := net.Pipe()
	defer bridgeSide.Close()
	defer peerSide.Close()

	bridge := newBridge(bridgeSide, log.New(io.Discard, "", 0), "127.0.0.1:31111")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readLoopErrCh := make(chan error, 1)
	go func() {
		readLoopErrCh <- bridge.readLoop(ctx)
	}()

	peerErrCh := make(chan error, 1)
	go func() {
		dec := gob.NewDecoder(peerSide)
		enc := gob.NewEncoder(peerSide)

		var req helperproto.Envelope
		if err := dec.Decode(&req); err != nil {
			peerErrCh <- err
			return
		}
		if req.ConnectRequest == nil {
			peerErrCh <- fmt.Errorf("expected connect request, got %#v", req)
			return
		}
		if err := enc.Encode(&helperproto.Envelope{
			ID: req.ID,
			ConnectResponse: &helperproto.ConnectResponse{
				StatusCode: http.StatusOK,
				Message:    "ok",
			},
		}); err != nil {
			peerErrCh <- err
			return
		}

		var frame helperproto.Envelope
		if err := dec.Decode(&frame); err != nil {
			peerErrCh <- err
			return
		}
		if frame.TunnelFrame == nil {
			peerErrCh <- fmt.Errorf("expected tunnel frame, got %#v", frame)
			return
		}
		if string(frame.TunnelFrame.Data) != "prefetch" {
			peerErrCh <- fmt.Errorf("unexpected tunnel frame payload %q", string(frame.TunnelFrame.Data))
			return
		}

		peerErrCh <- nil
	}()

	server := httptest.NewServer(bridge.proxyHandler())
	defer server.Close()

	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nprefetch"); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected connect 200, got %d", resp.StatusCode)
	}

	select {
	case err := <-peerErrCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for buffered payload frame")
	}

	cancel()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := peerSide.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readLoopErrCh:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected readLoop shutdown error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for readLoop to exit")
	}
}

func TestDeliverTunnelBackpressureDoesNotDropFrames(t *testing.T) {
	bridgeSide, peerSide := net.Pipe()
	defer bridgeSide.Close()
	defer peerSide.Close()

	bridge := newBridge(bridgeSide, log.New(io.Discard, "", 0), "127.0.0.1:31111")
	tunnelCh := bridge.registerTunnel(42)
	defer bridge.unregisterTunnel(42)

	for i := 0; i < cap(tunnelCh); i++ {
		bridge.deliverTunnel(helperproto.Envelope{
			ID: 42,
			TunnelFrame: &helperproto.TunnelFrame{
				Data: []byte{byte(i)},
			},
		})
	}

	blockedSendDone := make(chan struct{})
	go func() {
		bridge.deliverTunnel(helperproto.Envelope{
			ID: 42,
			TunnelFrame: &helperproto.TunnelFrame{
				Data: []byte{0xff},
			},
		})
		close(blockedSendDone)
	}()

	select {
	case <-blockedSendDone:
		t.Fatal("expected backpressure send to block when tunnel queue is full")
	case <-time.After(50 * time.Millisecond):
	}

	<-tunnelCh

	select {
	case <-blockedSendDone:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for blocked tunnel send to complete")
	}

	foundBlockedFrame := false
	for i := 0; i < cap(tunnelCh); i++ {
		env := <-tunnelCh
		if env.TunnelFrame != nil && len(env.TunnelFrame.Data) == 1 && env.TunnelFrame.Data[0] == 0xff {
			foundBlockedFrame = true
		}
	}
	if !foundBlockedFrame {
		t.Fatal("expected blocked frame to be delivered eventually, but it was lost")
	}
}

func TestHandleConnectCleansUpTunnelWhenConnectEstablishedWriteFails(t *testing.T) {
	bridgeSide, peerSide := net.Pipe()
	defer bridgeSide.Close()
	defer peerSide.Close()

	bridge := newBridge(bridgeSide, log.New(io.Discard, "", 0), "127.0.0.1:31111")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readLoopErrCh := make(chan error, 1)
	go func() {
		readLoopErrCh <- bridge.readLoop(ctx)
	}()

	peerErrCh := make(chan error, 1)
	go func() {
		dec := gob.NewDecoder(peerSide)
		enc := gob.NewEncoder(peerSide)

		var req helperproto.Envelope
		if err := dec.Decode(&req); err != nil {
			peerErrCh <- err
			return
		}
		if req.ConnectRequest == nil {
			peerErrCh <- fmt.Errorf("expected connect request, got %#v", req)
			return
		}
		if err := enc.Encode(&helperproto.Envelope{
			ID: req.ID,
			ConnectResponse: &helperproto.ConnectResponse{
				StatusCode: http.StatusOK,
				Message:    "ok",
			},
		}); err != nil {
			peerErrCh <- err
			return
		}

		var closeReq helperproto.Envelope
		if err := dec.Decode(&closeReq); err != nil {
			peerErrCh <- err
			return
		}
		if closeReq.TunnelClose == nil || closeReq.TunnelClose.Write {
			peerErrCh <- fmt.Errorf("expected terminal tunnel close after failed connect response write, got %#v", closeReq)
			return
		}

		peerErrCh <- nil
	}()

	req := httptest.NewRequest(http.MethodConnect, "http://proxy.invalid", nil)
	req.Host = "example.com:443"

	rw := &hijackableResponseWriter{
		conn: &failingWriteConn{writeErr: errors.New("boom")},
		rw:   bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriter(io.Discard)),
	}

	bridge.handleConnect(rw, req)

	select {
	case err := <-peerErrCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for tunnel close after failed 200 write")
	}

	bridge.tunnelMu.Lock()
	remaining := len(bridge.tunnels)
	bridge.tunnelMu.Unlock()
	if remaining != 0 {
		t.Fatalf("expected tunnel registry cleanup after failed 200 write, still have %d tunnel(s)", remaining)
	}

	cancel()
	if err := peerSide.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readLoopErrCh:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected readLoop shutdown error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for readLoop to exit")
	}
}

func TestRelayTunnelToPayloadHandlesShortWrites(t *testing.T) {
	bridge := newBridge(nil, log.New(io.Discard, "", 0), "127.0.0.1:31111")
	conn := &partialWriteConn{maxWrite: 2}
	tunnelCh := make(chan helperproto.Envelope, 2)
	tunnelCh <- helperproto.Envelope{
		ID: 7,
		TunnelFrame: &helperproto.TunnelFrame{
			Data: []byte("hello"),
		},
	}
	tunnelCh <- helperproto.Envelope{
		ID:          7,
		TunnelClose: &helperproto.TunnelClose{},
	}

	result := bridge.relayTunnelToPayload(context.Background(), conn, tunnelCh)
	if result.err != nil {
		t.Fatalf("expected relay to succeed, got %v", result.err)
	}
	if !result.terminal {
		t.Fatalf("expected terminal tunnel close result, got %#v", result)
	}
	if got := conn.writes.String(); got != "hello" {
		t.Fatalf("expected full payload to be written, got %q", got)
	}
}

func TestProxyHandlerTunnelDualHalfCloseCleansUp(t *testing.T) {
	bridgeSide, peerSide := net.Pipe()
	defer bridgeSide.Close()
	defer peerSide.Close()

	bridge := newBridge(bridgeSide, log.New(io.Discard, "", 0), "127.0.0.1:31111")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readLoopErrCh := make(chan error, 1)
	go func() {
		readLoopErrCh <- bridge.readLoop(ctx)
	}()

	peerErrCh := make(chan error, 1)
	go func() {
		dec := gob.NewDecoder(peerSide)
		enc := gob.NewEncoder(peerSide)

		var req helperproto.Envelope
		if err := dec.Decode(&req); err != nil {
			peerErrCh <- err
			return
		}
		if req.ConnectRequest == nil {
			peerErrCh <- fmt.Errorf("expected connect request, got %#v", req)
			return
		}
		if err := enc.Encode(&helperproto.Envelope{
			ID: req.ID,
			ConnectResponse: &helperproto.ConnectResponse{
				StatusCode: http.StatusOK,
				Message:    "ok",
			},
		}); err != nil {
			peerErrCh <- err
			return
		}
		if err := enc.Encode(&helperproto.Envelope{
			ID: req.ID,
			TunnelClose: &helperproto.TunnelClose{
				Write: true,
			},
		}); err != nil {
			peerErrCh <- err
			return
		}

		var closeFromHelper helperproto.Envelope
		if err := dec.Decode(&closeFromHelper); err != nil {
			peerErrCh <- err
			return
		}
		if closeFromHelper.TunnelClose == nil || !closeFromHelper.TunnelClose.Write {
			peerErrCh <- fmt.Errorf("expected write-half close from helper, got %#v", closeFromHelper)
			return
		}

		peerErrCh <- nil
	}()

	server := httptest.NewServer(bridge.proxyHandler())
	defer server.Close()

	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected connect 200, got %d", resp.StatusCode)
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("expected *net.TCPConn, got %T", conn)
	}
	if err := tcpConn.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-peerErrCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for dual half-close exchange")
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		bridge.tunnelMu.Lock()
		n := len(bridge.tunnels)
		bridge.tunnelMu.Unlock()
		if n == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	bridge.tunnelMu.Lock()
	remaining := len(bridge.tunnels)
	bridge.tunnelMu.Unlock()
	if remaining != 0 {
		t.Fatalf("expected tunnel registry cleanup after dual half-close, still have %d tunnel(s)", remaining)
	}

	cancel()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := peerSide.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readLoopErrCh:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected readLoop shutdown error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for readLoop to exit")
	}
}

func startReadLoop(t *testing.T, proxyAddr string) (net.Conn, net.Conn, <-chan error) {
	t.Helper()

	bridgeSide, peerSide := net.Pipe()
	bridge := newBridge(bridgeSide, log.New(io.Discard, "", 0), proxyAddr)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	errCh := make(chan error, 1)
	go func() {
		errCh <- bridge.readLoop(ctx)
	}()

	return bridgeSide, peerSide, errCh
}

func closeReadLoop(t *testing.T, peer net.Conn, errCh <-chan error) {
	t.Helper()

	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("unexpected readLoop shutdown error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for readLoop to exit")
	}
}

type hijackableResponseWriter struct {
	header http.Header
	conn   net.Conn
	rw     *bufio.ReadWriter
}

func (w *hijackableResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *hijackableResponseWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func (w *hijackableResponseWriter) WriteHeader(statusCode int) {}

func (w *hijackableResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, w.rw, nil
}

type failingWriteConn struct {
	writeErr error
	closed   bool
}

func (c *failingWriteConn) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c *failingWriteConn) Write(_ []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return 0, nil
}

func (c *failingWriteConn) Close() error {
	c.closed = true
	return nil
}

func (c *failingWriteConn) LocalAddr() net.Addr  { return dummyAddr("local") }
func (c *failingWriteConn) RemoteAddr() net.Addr { return dummyAddr("remote") }

func (c *failingWriteConn) SetDeadline(_ time.Time) error      { return nil }
func (c *failingWriteConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *failingWriteConn) SetWriteDeadline(_ time.Time) error { return nil }

type partialWriteConn struct {
	writes   bytes.Buffer
	maxWrite int
}

func (c *partialWriteConn) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c *partialWriteConn) Write(p []byte) (int, error) {
	n := len(p)
	if c.maxWrite > 0 && n > c.maxWrite {
		n = c.maxWrite
	}
	if n == 0 {
		return 0, nil
	}
	if _, err := c.writes.Write(p[:n]); err != nil {
		return 0, err
	}
	return n, nil
}

func (c *partialWriteConn) Close() error                       { return nil }
func (c *partialWriteConn) LocalAddr() net.Addr                { return dummyAddr("local") }
func (c *partialWriteConn) RemoteAddr() net.Addr               { return dummyAddr("remote") }
func (c *partialWriteConn) SetDeadline(_ time.Time) error      { return nil }
func (c *partialWriteConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *partialWriteConn) SetWriteDeadline(_ time.Time) error { return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }
