package helperruntime

import (
	"context"
	"encoding/gob"
	"errors"
	"io"
	"log"
	"net"
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
