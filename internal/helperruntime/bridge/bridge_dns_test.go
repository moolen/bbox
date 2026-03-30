package bridge

import (
	"context"
	"encoding/gob"
	"io"
	"log"
	"net"
	"testing"

	"github.com/moolen/bbox/internal/helperproto"
)

func TestRuntimeBridgeDNSRoundTrip(t *testing.T) {
	bridgeConn, peerConn := net.Pipe()
	defer bridgeConn.Close()
	defer peerConn.Close()

	rtBridge := New(bridgeConn, log.New(io.Discard, "", 0), "")

	errCh := make(chan error, 1)
	go func() {
		dec := gob.NewDecoder(peerConn)
		enc := gob.NewEncoder(peerConn)

		var req helperproto.Envelope
		if err := dec.Decode(&req); err != nil {
			errCh <- err
			return
		}
		if req.DNSRequest == nil {
			t.Errorf("first envelope kind = %q, want dns_request", req.Kind())
			errCh <- nil
			return
		}
		if err := enc.Encode(&helperproto.Envelope{
			ID: req.ID,
			DNSResponse: &helperproto.DNSResponse{
				Payload: []byte{0xca, 0xfe, 0xba, 0xbe},
			},
		}); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	go func() {
		_ = rtBridge.ReadLoop(context.Background())
	}()

	payload, err := rtBridge.DNSRoundTrip(context.Background(), helperproto.DNSRequest{
		Network: "udp",
		Host:    "1.1.1.1",
		Port:    53,
		Payload: []byte{0xde, 0xad, 0xbe, 0xef},
	})
	if err != nil {
		t.Fatalf("DNSRoundTrip() error = %v", err)
	}
	if string(payload) != string([]byte{0xca, 0xfe, 0xba, 0xbe}) {
		t.Fatalf("DNSRoundTrip() payload = %x, want %x", payload, []byte{0xca, 0xfe, 0xba, 0xbe})
	}

	if err := <-errCh; err != nil {
		t.Fatalf("peer loop error = %v", err)
	}
}
