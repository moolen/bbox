package helperproto

import (
	"bytes"
	"encoding/gob"
	"net/http"
	"testing"
)

func TestExecRequestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)

	want := ExecRequest{
		Argv:        []string{"/usr/bin/curl", "-v", "http://example.com"},
		Env:         []string{"HTTP_PROXY=http://127.0.0.1:31111"},
		Interactive: true,
		Terminal:    true,
		InitialSize: &TerminalSize{Rows: 24, Cols: 80},
	}
	if err := enc.Encode(&want); err != nil {
		t.Fatal(err)
	}

	var got ExecRequest
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Argv) != 3 {
		t.Fatalf("unexpected argv: %#v", got.Argv)
	}
	if !got.Interactive || !got.Terminal {
		t.Fatalf("unexpected interactive flags: %#v", got)
	}
	if got.InitialSize == nil || got.InitialSize.Rows != 24 || got.InitialSize.Cols != 80 {
		t.Fatalf("unexpected initial size: %#v", got.InitialSize)
	}
}

func TestExecInputRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)

	want := ExecInput{
		Data:   []byte("hello"),
		EOF:    true,
		Cancel: true,
		Resize: &TerminalSize{Rows: 42, Cols: 120},
	}
	if err := enc.Encode(&want); err != nil {
		t.Fatal(err)
	}

	var got ExecInput
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Data, want.Data) || !got.EOF || !got.Cancel {
		t.Fatalf("unexpected exec input payload: got=%#v want=%#v", got, want)
	}
	if got.Resize == nil || got.Resize.Rows != want.Resize.Rows || got.Resize.Cols != want.Resize.Cols {
		t.Fatalf("unexpected resize payload: got=%#v want=%#v", got.Resize, want.Resize)
	}
}

func TestConnectRequestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)

	want := Envelope{
		ID: 9,
		ConnectRequest: &ConnectRequest{
			Host:        "example.com",
			Port:        443,
			Transparent: true,
			ProtocolMetadata: ProtocolMetadata{
				Protocol:   "mysql",
				Source:     "first_bytes",
				Confidence: "definite",
			},
		},
	}
	if err := enc.Encode(&want); err != nil {
		t.Fatal(err)
	}

	var got Envelope
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID {
		t.Fatalf("unexpected envelope id: got=%d want=%d", got.ID, want.ID)
	}
	if got.ConnectRequest == nil {
		t.Fatalf("unexpected connect request: %#v", got.ConnectRequest)
	}
	if got.ConnectRequest.Host != want.ConnectRequest.Host ||
		got.ConnectRequest.Port != want.ConnectRequest.Port ||
		got.ConnectRequest.Transparent != want.ConnectRequest.Transparent ||
		got.ConnectRequest.ProtocolMetadata != want.ConnectRequest.ProtocolMetadata {
		t.Fatalf("unexpected connect request payload: got=%#v want=%#v", got.ConnectRequest, want.ConnectRequest)
	}
}

func TestConnectResponseRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)

	want := Envelope{
		ID: 10,
		ConnectResponse: &ConnectResponse{
			StatusCode: 407,
			Message:    "Proxy Authentication Required",
			Error:      "missing credentials",
		},
	}
	if err := enc.Encode(&want); err != nil {
		t.Fatal(err)
	}

	var got Envelope
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID {
		t.Fatalf("unexpected envelope id: got=%d want=%d", got.ID, want.ID)
	}
	if got.ConnectResponse == nil {
		t.Fatalf("unexpected connect response: %#v", got.ConnectResponse)
	}
	if got.ConnectResponse.StatusCode != want.ConnectResponse.StatusCode ||
		got.ConnectResponse.Message != want.ConnectResponse.Message ||
		got.ConnectResponse.Error != want.ConnectResponse.Error {
		t.Fatalf("unexpected connect response payload: got=%#v want=%#v", got.ConnectResponse, want.ConnectResponse)
	}
}

func TestDNSRequestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)

	want := Envelope{
		ID: 17,
		DNSRequest: &DNSRequest{
			Network: "udp",
			Host:    "8.8.8.8",
			Port:    53,
			Payload: []byte{0xde, 0xad},
		},
	}
	if err := enc.Encode(&want); err != nil {
		t.Fatal(err)
	}

	var got Envelope
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID {
		t.Fatalf("unexpected envelope id: got=%d want=%d", got.ID, want.ID)
	}
	if got.DNSRequest == nil {
		t.Fatalf("unexpected dns request: %#v", got.DNSRequest)
	}
	if got.DNSRequest.Network != want.DNSRequest.Network ||
		got.DNSRequest.Host != want.DNSRequest.Host ||
		got.DNSRequest.Port != want.DNSRequest.Port ||
		!bytes.Equal(got.DNSRequest.Payload, want.DNSRequest.Payload) {
		t.Fatalf("unexpected dns request payload: got=%#v want=%#v", got.DNSRequest, want.DNSRequest)
	}
}

func TestDNSResponseRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)

	want := Envelope{
		ID: 18,
		DNSResponse: &DNSResponse{
			Payload: []byte{0xca, 0xfe},
			Error:   "upstream timeout",
		},
	}
	if err := enc.Encode(&want); err != nil {
		t.Fatal(err)
	}

	var got Envelope
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID {
		t.Fatalf("unexpected envelope id: got=%d want=%d", got.ID, want.ID)
	}
	if got.DNSResponse == nil {
		t.Fatalf("unexpected dns response: %#v", got.DNSResponse)
	}
	if !bytes.Equal(got.DNSResponse.Payload, want.DNSResponse.Payload) || got.DNSResponse.Error != want.DNSResponse.Error {
		t.Fatalf("unexpected dns response payload: got=%#v want=%#v", got.DNSResponse, want.DNSResponse)
	}
}

func TestTunnelFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)

	want := Envelope{
		ID: 11,
		TunnelFrame: &TunnelFrame{
			Data: []byte("hello"),
		},
	}
	if err := enc.Encode(&want); err != nil {
		t.Fatal(err)
	}

	var got Envelope
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID {
		t.Fatalf("unexpected envelope id: got=%d want=%d", got.ID, want.ID)
	}
	if got.TunnelFrame == nil {
		t.Fatalf("unexpected tunnel frame: %#v", got.TunnelFrame)
	}
	if !bytes.Equal(got.TunnelFrame.Data, want.TunnelFrame.Data) {
		t.Fatalf("unexpected tunnel frame payload: got=%#v want=%#v", got.TunnelFrame, want.TunnelFrame)
	}
}

func TestTunnelCloseRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)

	want := Envelope{
		ID: 12,
		TunnelClose: &TunnelClose{
			Write: true,
			Error: "EOF",
		},
	}
	if err := enc.Encode(&want); err != nil {
		t.Fatal(err)
	}

	var got Envelope
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID {
		t.Fatalf("unexpected envelope id: got=%d want=%d", got.ID, want.ID)
	}
	if got.TunnelClose == nil {
		t.Fatalf("unexpected tunnel close: %#v", got.TunnelClose)
	}
	if got.TunnelClose.Write != want.TunnelClose.Write || got.TunnelClose.Error != want.TunnelClose.Error {
		t.Fatalf("unexpected tunnel close payload: got=%#v want=%#v", got.TunnelClose, want.TunnelClose)
	}
}

func TestMITMRequestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)

	want := Envelope{
		ID: 13,
		MITMRequest: &MITMRequest{
			Scheme:       "https",
			Authority:    "example.com:443",
			Host:         "example.com",
			Method:       "POST",
			Path:         "/v1/chat/completions",
			RawQuery:     "stream=true",
			Header:       http.Header{"Content-Type": []string{"application/json"}},
			Body:         []byte(`{"hello":"world"}`),
			Proto:        "HTTP/2.0",
			BodyTooLarge: true,
		},
	}
	if err := enc.Encode(&want); err != nil {
		t.Fatal(err)
	}

	var got Envelope
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID {
		t.Fatalf("unexpected envelope id: got=%d want=%d", got.ID, want.ID)
	}
	if got.MITMRequest == nil {
		t.Fatalf("unexpected MITM request: %#v", got.MITMRequest)
	}
	if got.MITMRequest.Host != want.MITMRequest.Host || got.MITMRequest.Proto != want.MITMRequest.Proto {
		t.Fatalf("unexpected MITM request payload: got=%#v want=%#v", got.MITMRequest, want.MITMRequest)
	}
}

func TestMITMResponseRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)

	want := Envelope{
		ID: 14,
		MITMResponse: &MITMResponse{
			StatusCode: 201,
			Header:     http.Header{"X-Test": []string{"ok"}},
			Body:       []byte("created"),
			Error:      "upstream warning",
		},
	}
	if err := enc.Encode(&want); err != nil {
		t.Fatal(err)
	}

	var got Envelope
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID {
		t.Fatalf("unexpected envelope id: got=%d want=%d", got.ID, want.ID)
	}
	if got.MITMResponse == nil {
		t.Fatalf("unexpected MITM response: %#v", got.MITMResponse)
	}
	if got.MITMResponse.StatusCode != want.MITMResponse.StatusCode ||
		got.MITMResponse.Error != want.MITMResponse.Error {
		t.Fatalf("unexpected MITM response payload: got=%#v want=%#v", got.MITMResponse, want.MITMResponse)
	}
}

func TestLeafCertRequestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)

	want := Envelope{
		ID: 15,
		LeafCertRequest: &LeafCertRequest{
			Host: "example.com",
		},
	}
	if err := enc.Encode(&want); err != nil {
		t.Fatal(err)
	}

	var got Envelope
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID {
		t.Fatalf("unexpected envelope id: got=%d want=%d", got.ID, want.ID)
	}
	if got.LeafCertRequest == nil || got.LeafCertRequest.Host != "example.com" {
		t.Fatalf("unexpected leaf cert request: %#v", got.LeafCertRequest)
	}
}

func TestLeafCertResponseRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)

	want := Envelope{
		ID: 16,
		LeafCertResponse: &LeafCertResponse{
			CertPEM: []byte("cert"),
			KeyPEM:  []byte("key"),
			Error:   "boom",
		},
	}
	if err := enc.Encode(&want); err != nil {
		t.Fatal(err)
	}

	var got Envelope
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID {
		t.Fatalf("unexpected envelope id: got=%d want=%d", got.ID, want.ID)
	}
	if got.LeafCertResponse == nil || got.LeafCertResponse.Error != "boom" {
		t.Fatalf("unexpected leaf cert response: %#v", got.LeafCertResponse)
	}
}

func TestReadyRoundTripIncludesTrafficModeAddrs(t *testing.T) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)

	want := Envelope{
		Ready: &Ready{
			ProtocolVersion: ProtocolVersion,
			ProxyAddr:       "127.0.0.1:31111",
			DNSAddr:         "127.0.0.1:53",
			TCPAddr:         "127.0.0.1:18080",
		},
	}
	if err := enc.Encode(&want); err != nil {
		t.Fatal(err)
	}

	var got Envelope
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Ready == nil {
		t.Fatalf("unexpected ready payload: %#v", got.Ready)
	}
	if got.Ready.ProtocolVersion != want.Ready.ProtocolVersion {
		t.Fatalf("unexpected protocol version: got=%d want=%d", got.Ready.ProtocolVersion, want.Ready.ProtocolVersion)
	}
	if got.Ready.ProxyAddr != want.Ready.ProxyAddr {
		t.Fatalf("unexpected proxy address: got=%q want=%q", got.Ready.ProxyAddr, want.Ready.ProxyAddr)
	}
	if got.Ready.DNSAddr != want.Ready.DNSAddr {
		t.Fatalf("unexpected DNS address: got=%q want=%q", got.Ready.DNSAddr, want.Ready.DNSAddr)
	}
	if got.Ready.TCPAddr != want.Ready.TCPAddr {
		t.Fatalf("unexpected TCP address: got=%q want=%q", got.Ready.TCPAddr, want.Ready.TCPAddr)
	}
}

func TestProtocolVersion(t *testing.T) {
	if ProtocolVersion != 9 {
		t.Fatalf("unexpected protocol version: got=%d want=%d", ProtocolVersion, 9)
	}
}

func TestEnvelopeKind(t *testing.T) {
	tests := []struct {
		name string
		env  Envelope
		want string
	}{
		{
			name: "hello",
			env:  Envelope{Hello: &Hello{}},
			want: "hello",
		},
		{
			name: "ready",
			env:  Envelope{Ready: &Ready{}},
			want: "ready",
		},
		{
			name: "proxy_request",
			env:  Envelope{ProxyRequest: &ProxyRequest{}},
			want: "proxy_request",
		},
		{
			name: "proxy_response",
			env:  Envelope{ProxyResponse: &ProxyResponse{}},
			want: "proxy_response",
		},
		{
			name: "exec_request",
			env:  Envelope{ExecRequest: &ExecRequest{}},
			want: "exec_request",
		},
		{
			name: "exec_input",
			env:  Envelope{ExecInput: &ExecInput{}},
			want: "exec_input",
		},
		{
			name: "stream_frame",
			env:  Envelope{StreamFrame: &StreamFrame{}},
			want: "stream_frame",
		},
		{
			name: "exec_result",
			env:  Envelope{ExecResult: &ExecResult{}},
			want: "exec_result",
		},
		{
			name: "connect_request",
			env:  Envelope{ConnectRequest: &ConnectRequest{}},
			want: "connect_request",
		},
		{
			name: "connect_response",
			env:  Envelope{ConnectResponse: &ConnectResponse{}},
			want: "connect_response",
		},
		{
			name: "dns_request",
			env:  Envelope{DNSRequest: &DNSRequest{}},
			want: "dns_request",
		},
		{
			name: "dns_response",
			env:  Envelope{DNSResponse: &DNSResponse{}},
			want: "dns_response",
		},
		{
			name: "tunnel_frame",
			env:  Envelope{TunnelFrame: &TunnelFrame{}},
			want: "tunnel_frame",
		},
		{
			name: "tunnel_close",
			env:  Envelope{TunnelClose: &TunnelClose{}},
			want: "tunnel_close",
		},
		{
			name: "mitm_request",
			env:  Envelope{MITMRequest: &MITMRequest{}},
			want: "mitm_request",
		},
		{
			name: "leaf_cert_request",
			env:  Envelope{LeafCertRequest: &LeafCertRequest{}},
			want: "leaf_cert_request",
		},
		{
			name: "leaf_cert_response",
			env:  Envelope{LeafCertResponse: &LeafCertResponse{}},
			want: "leaf_cert_response",
		},
		{
			name: "mitm_response",
			env:  Envelope{MITMResponse: &MITMResponse{}},
			want: "mitm_response",
		},
		{
			name: "unknown",
			env:  Envelope{},
			want: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.env.Kind(); got != tt.want {
				t.Fatalf("Kind() = %q, want %q", got, tt.want)
			}
		})
	}
}
