package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moolen/bbox"
)

const grpcLikeClientSource = `package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type result struct {
	Proto       string ` + "`json:\"proto\"`" + `
	ContentType string ` + "`json:\"content_type\"`" + `
	BodyLen     int    ` + "`json:\"body_len\"`" + `
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <url> <proxy-url>\n", os.Args[0])
		os.Exit(2)
	}

	targetURL := os.Args[1]
	proxyURL, err := url.Parse(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid proxy url %q: %v\n", os.Args[2], err)
		os.Exit(2)
	}

	transport := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return proxyURL, nil
		},
		ForceAttemptHTTP2: true,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, targetURL, strings.NewReader(string([]byte{0x00, 0x00, 0x00, 0x00, 0x00})))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/grpc+proto")
	req.Header.Set("Te", "trailers")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "unexpected status %d body=%x\n", resp.StatusCode, body)
		os.Exit(1)
	}
	if !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "application/grpc") {
		fmt.Fprintf(os.Stderr, "unexpected content-type %q\n", resp.Header.Get("Content-Type"))
		os.Exit(1)
	}
	if len(body) != 5 {
		fmt.Fprintf(os.Stderr, "unexpected body len %d\n", len(body))
		os.Exit(1)
	}

	if err := json.NewEncoder(os.Stdout).Encode(result{
		Proto:       resp.Proto,
		ContentType: resp.Header.Get("Content-Type"),
		BodyLen:     len(body),
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
`

type grpcLikeClientResult struct {
	Proto       string `json:"proto"`
	ContentType string `json:"content_type"`
	BodyLen     int    `json:"body_len"`
}

func TestSandboxMITMClassifiesGRPC(t *testing.T) {
	requireSandboxPrereqs(t)

	server := startTrustedHTTP2TLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/grpc" {
			http.NotFound(w, r)
			return
		}
		if r.ProtoMajor != 2 {
			t.Fatalf("expected HTTP/2 request, got %q", r.Proto)
		}
		if got := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(got), "application/grpc") {
			t.Fatalf("expected gRPC content-type, got %q", got)
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00})
	}))
	defer server.Close()
	trustHTTPSServer(t, server)

	clientBinary := buildStaticTestClient(t, "grpc-like-client", grpcLikeClientSource)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	logger := &recordingAccessLogger{}
	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{
		MITM:         bbox.MITMOptions{Enabled: true},
		AccessLogger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("close manager: %v", err)
		}
	}()

	sandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "mitm-grpc",
		Binaries: []string{clientBinary},
		Mounts: []bbox.Mount{
			{Source: filepath.Dir(clientBinary), Target: "/workspace", ReadOnly: true},
		},
		Policy: bbox.NetworkPolicy{
			Rules: []bbox.PolicyRule{
				{
					HostPatterns: []string{`^127[.]0[.]0[.]1$`},
					ConnectPorts: []string{mustPortForServer(t, server)},
				},
				{
					HostPatterns: []string{`^127[.]0[.]0[.]1$`},
					HTTPMethods:  []string{http.MethodPost},
					PathPatterns: []string{`^/grpc$`},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("create gRPC sandbox: %v", err)
	}
	defer func() {
		if err := sandbox.Close(); err != nil {
			t.Fatalf("close gRPC sandbox: %v", err)
		}
	}()

	result, err := sandbox.Run(ctx, []string{
		"/workspace/" + filepath.Base(clientBinary),
		server.URL + "/grpc",
		sandbox.ProxyURL(),
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("run gRPC-like client: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("expected gRPC-like client to succeed, exit=%d stdout=%q stderr=%q", result.ExitCode, string(result.Stdout), string(result.Stderr))
	}

	var decoded grpcLikeClientResult
	if err := json.Unmarshal(result.Stdout, &decoded); err != nil {
		t.Fatalf("decode gRPC-like client result: %v stdout=%q", err, string(result.Stdout))
	}
	if decoded.Proto != "HTTP/2.0" {
		t.Fatalf("expected HTTP/2.0 response protocol, got %q", decoded.Proto)
	}
	if !strings.HasPrefix(strings.ToLower(decoded.ContentType), "application/grpc") {
		t.Fatalf("expected application/grpc content type, got %q", decoded.ContentType)
	}
	if decoded.BodyLen != 5 {
		t.Fatalf("expected 5-byte gRPC frame, got %d", decoded.BodyLen)
	}

	entry, ok := findSandboxAccessLogEntry(logger.snapshot(), "mitm-grpc", "mitm")
	if !ok {
		t.Fatalf("expected MITM access log entry, got %#v", logger.snapshot())
	}
	if entry.Protocol != "grpc" {
		t.Fatalf("expected protocol grpc, got %#v", entry)
	}
	if entry.ProtocolSource != "http_headers" {
		t.Fatalf("expected protocol source http_headers, got %#v", entry)
	}
	if entry.ProtocolConfidence != "definite" {
		t.Fatalf("expected protocol confidence definite, got %#v", entry)
	}
}
