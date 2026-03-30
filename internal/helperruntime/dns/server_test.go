package dns

import (
	"encoding/binary"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestServerHandleQueryReturnsLoopbackARecord(t *testing.T) {
	t.Parallel()

	payload := mustDNSQuery(t, dnsmessage.TypeA)

	response, ok := HandleQuery(payload)
	if !ok || response == nil {
		t.Fatal("expected loopback DNS response")
	}

	var message dnsmessage.Message
	if err := message.Unpack(response); err != nil {
		t.Fatalf("unpack DNS response: %v", err)
	}

	if len(message.Answers) != 1 {
		t.Fatalf("unexpected number of answers: got %d want 1", len(message.Answers))
	}

	answer, ok := message.Answers[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("unexpected answer type: got %T", message.Answers[0].Body)
	}
	if got := net.IP(answer.A[:]).String(); got != "127.0.0.1" {
		t.Fatalf("unexpected A record: got %q want %q", got, "127.0.0.1")
	}
}

func TestServeTCPConnRejectsOversizedLength(t *testing.T) {
	t.Parallel()

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- serveTCPConn(serverConn)
	}()

	oversized := maxTCPPayloadSize + 1
	var lengthBuf [2]byte
	binary.BigEndian.PutUint16(lengthBuf[:], uint16(oversized))
	if _, err := clientConn.Write(lengthBuf[:]); err != nil {
		t.Fatalf("write oversized DNS TCP frame: %v", err)
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected oversized DNS TCP frame to be rejected")
		}
		if !strings.Contains(err.Error(), "exceeds maximum") {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for oversized DNS TCP frame rejection")
	}
}

func TestNewServerRetriesEphemeralPortWhenUDPBindRaces(t *testing.T) {
	origListenTCP := listenTCP
	origListenPacket := listenPacket
	t.Cleanup(func() {
		listenTCP = origListenTCP
		listenPacket = origListenPacket
	})

	tcpAttempts := 0
	udpAttempts := 0
	listenTCP = func(network, addr string) (net.Listener, error) {
		tcpAttempts++
		return net.Listen(network, addr)
	}
	listenPacket = func(network, addr string) (net.PacketConn, error) {
		udpAttempts++
		if udpAttempts == 1 {
			return nil, &net.OpError{Op: "listen", Net: network, Err: syscall.EADDRINUSE}
		}
		return net.ListenPacket(network, addr)
	}

	server, err := NewServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	t.Cleanup(func() {
		_ = server.Close()
	})

	if tcpAttempts < 2 {
		t.Fatalf("expected at least 2 TCP listen attempts, got %d", tcpAttempts)
	}
	if udpAttempts < 2 {
		t.Fatalf("expected at least 2 UDP listen attempts, got %d", udpAttempts)
	}
}

func mustDNSQuery(t *testing.T, queryType dnsmessage.Type) []byte {
	t.Helper()

	name, err := dnsmessage.NewName("example.com.")
	if err != nil {
		t.Fatalf("construct DNS name: %v", err)
	}

	payload, err := (&dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               7,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  queryType,
			Class: dnsmessage.ClassINET,
		}},
	}).Pack()
	if err != nil {
		t.Fatalf("pack DNS query: %v", err)
	}

	return payload
}
