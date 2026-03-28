package dns

import (
	"net"
	"testing"

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
