package helperruntime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/gob"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moolen/bbox/internal/helperproto"
	"golang.org/x/net/dns/dnsmessage"
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

func TestRunTransparentRequiresAllListeners(t *testing.T) {
	t.Parallel()

	blockedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blockedListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = Run(ctx, Config{
		Bridge:      newTestBridge(),
		TrafficMode: TrafficModeTransparent,
		MITMEnabled: true,
		DNSAddr:     "127.0.0.1:0",
		HTTPAddr:    blockedListener.Addr().String(),
		HTTPSAddr:   "127.0.0.1:0",
	})
	if err == nil {
		t.Fatal("expected transparent startup to fail when a listener cannot bind")
	}
}

func TestTransparentDNSReturnsLoopbackForAQuery(t *testing.T) {
	dnsAddr, shutdown := startTransparentRuntime(t)
	defer shutdown()

	response := exchangeTransparentDNS(t, "udp", dnsAddr, dnsmessage.TypeA)

	if got := response.Header.RCode; got != dnsmessage.RCodeSuccess {
		t.Fatalf("unexpected DNS rcode: got %v want %v", got, dnsmessage.RCodeSuccess)
	}
	if len(response.Answers) != 1 {
		t.Fatalf("unexpected number of answers: got %d want 1", len(response.Answers))
	}

	answer, ok := response.Answers[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("unexpected answer type: got %T", response.Answers[0].Body)
	}
	if got := net.IP(answer.A[:]).String(); got != "127.0.0.1" {
		t.Fatalf("unexpected A record: got %q want %q", got, "127.0.0.1")
	}
}

func TestTransparentDNSReturnsEmptySuccessForAAAAQuery(t *testing.T) {
	dnsAddr, shutdown := startTransparentRuntime(t)
	defer shutdown()

	response := exchangeTransparentDNS(t, "udp", dnsAddr, dnsmessage.TypeAAAA)

	if got := response.Header.RCode; got != dnsmessage.RCodeSuccess {
		t.Fatalf("unexpected DNS rcode: got %v want %v", got, dnsmessage.RCodeSuccess)
	}
	if len(response.Answers) != 0 {
		t.Fatalf("unexpected number of answers: got %d want 0", len(response.Answers))
	}
}

func TestTransparentDNSRefusesUnsupportedQueryType(t *testing.T) {
	dnsAddr, shutdown := startTransparentRuntime(t)
	defer shutdown()

	response := exchangeTransparentDNS(t, "udp", dnsAddr, dnsmessage.TypeMX)

	if got := response.Header.RCode; got != dnsmessage.RCodeRefused {
		t.Fatalf("unexpected DNS rcode: got %v want %v", got, dnsmessage.RCodeRefused)
	}
	if len(response.Answers) != 0 {
		t.Fatalf("unexpected number of answers: got %d want 0", len(response.Answers))
	}
}

func TestTransparentDNSHandlesTCPAndUDP(t *testing.T) {
	dnsAddr, shutdown := startTransparentRuntime(t)
	defer shutdown()

	for _, network := range []string{"udp", "tcp"} {
		network := network
		t.Run(network, func(t *testing.T) {
			response := exchangeTransparentDNS(t, network, dnsAddr, dnsmessage.TypeA)

			if got := response.Header.RCode; got != dnsmessage.RCodeSuccess {
				t.Fatalf("unexpected DNS rcode: got %v want %v", got, dnsmessage.RCodeSuccess)
			}
			if len(response.Answers) != 1 {
				t.Fatalf("unexpected number of answers: got %d want 1", len(response.Answers))
			}

			answer, ok := response.Answers[0].Body.(*dnsmessage.AResource)
			if !ok {
				t.Fatalf("unexpected answer type: got %T", response.Answers[0].Body)
			}
			if got := net.IP(answer.A[:]).String(); got != "127.0.0.1" {
				t.Fatalf("unexpected A record: got %q want %q", got, "127.0.0.1")
			}
		})
	}
}

func TestTransparentHTTPRejectsMissingHost(t *testing.T) {
	ready, shutdown := startTransparentRuntimeReady(t)
	defer shutdown()

	conn, err := net.Dial("tcp", ready.HTTPAddr)
	if err != nil {
		t.Fatalf("dial transparent HTTP listener: %v", err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "GET /missing-host HTTP/1.0\r\n\r\n"); err != nil {
		t.Fatalf("write transparent HTTP request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read transparent HTTP response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unexpected status: got %d want %d", resp.StatusCode, http.StatusBadRequest)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if !strings.Contains(string(body), "host is required") {
		t.Fatalf("unexpected response body: %q", string(body))
	}
}

func TestTransparentHTTPNormalizesOriginFormRequest(t *testing.T) {
	bridgeSide, peerSide := net.Pipe()
	defer peerSide.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			Bridge:      bridgeSide,
			TrafficMode: TrafficModeTransparent,
			DNSAddr:     "127.0.0.1:0",
			HTTPAddr:    "127.0.0.1:0",
			HTTPSAddr:   "127.0.0.1:0",
			Logger:      log.New(io.Discard, "", 0),
		})
	}()

	enc := gob.NewEncoder(peerSide)
	dec := gob.NewDecoder(peerSide)
	if err := enc.Encode(&helperproto.Envelope{
		ID: 1,
		Hello: &helperproto.Hello{
			ProtocolVersion: helperproto.ProtocolVersion,
			SandboxID:       "transparent-http-test",
		},
	}); err != nil {
		t.Fatalf("send hello: %v", err)
	}

	var ready helperproto.Envelope
	if err := dec.Decode(&ready); err != nil {
		t.Fatalf("read ready: %v", err)
	}
	if ready.Ready == nil {
		t.Fatalf("expected ready response, got %#v", ready)
	}
	if ready.Ready.HTTPAddr == "" {
		t.Fatal("expected transparent runtime to report an HTTP address")
	}

	peerErrCh := make(chan error, 1)
	go func() {
		var req helperproto.Envelope
		if err := dec.Decode(&req); err != nil {
			peerErrCh <- err
			return
		}
		if req.ProxyRequest == nil {
			peerErrCh <- fmt.Errorf("expected proxy request, got %#v", req)
			return
		}
		if req.ProxyRequest.Method != http.MethodGet {
			peerErrCh <- fmt.Errorf("unexpected method: got %q", req.ProxyRequest.Method)
			return
		}
		if req.ProxyRequest.URL != "http://example.com/normalized/path?hello=world" {
			peerErrCh <- fmt.Errorf("unexpected normalized URL: got %q", req.ProxyRequest.URL)
			return
		}
		if got := req.ProxyRequest.Header.Get("Proxy-Connection"); got != "" {
			peerErrCh <- fmt.Errorf("expected Proxy-Connection header to be stripped, got %q", got)
			return
		}
		if got := req.ProxyRequest.Header.Get("X-Test"); got != "present" {
			peerErrCh <- fmt.Errorf("expected X-Test header to survive, got %q", got)
			return
		}
		if err := enc.Encode(&helperproto.Envelope{
			ID: req.ID,
			ProxyResponse: &helperproto.ProxyResponse{
				StatusCode: http.StatusNoContent,
				Header:     make(http.Header),
			},
		}); err != nil {
			peerErrCh <- err
			return
		}
		peerErrCh <- nil
	}()

	conn, err := net.Dial("tcp", ready.Ready.HTTPAddr)
	if err != nil {
		t.Fatalf("dial transparent HTTP listener: %v", err)
	}
	defer conn.Close()

	request := strings.Join([]string{
		"GET /normalized/path?hello=world HTTP/1.1",
		"Host: example.com",
		"Proxy-Connection: keep-alive",
		"X-Test: present",
		"",
		"",
	}, "\r\n")
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write transparent HTTP request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read transparent HTTP response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected status: got %d want %d", resp.StatusCode, http.StatusNoContent)
	}

	select {
	case err := <-peerErrCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for proxy request")
	}

	cancel()
	_ = peerSide.Close()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected transparent runtime shutdown error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for transparent runtime to exit")
	}
}

func TestProxyHandlerMITMHTTP1ForwardsInterceptedRequest(t *testing.T) {
	bridgeSide, peerSide := net.Pipe()
	defer bridgeSide.Close()
	defer peerSide.Close()

	bridge := newBridge(bridgeSide, log.New(io.Discard, "", 0), "127.0.0.1:31111")
	bridge.mitmEnabled = true
	bridge.maxRequestBodyBytes = 1024

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readLoopErrCh := make(chan error, 1)
	go func() {
		readLoopErrCh <- bridge.readLoop(ctx)
	}()

	caRoots, certPEM, keyPEM := issueTestLeafCertPEM(t, "example.com")

	peerErrCh := make(chan error, 1)
	go func() {
		dec := gob.NewDecoder(peerSide)
		enc := gob.NewEncoder(peerSide)

		var connectReq helperproto.Envelope
		if err := dec.Decode(&connectReq); err != nil {
			peerErrCh <- err
			return
		}
		if connectReq.ConnectRequest == nil {
			peerErrCh <- fmt.Errorf("expected connect request, got %#v", connectReq)
			return
		}
		if err := enc.Encode(&helperproto.Envelope{
			ID: connectReq.ID,
			ConnectResponse: &helperproto.ConnectResponse{
				StatusCode: http.StatusOK,
			},
		}); err != nil {
			peerErrCh <- err
			return
		}

		var certReq helperproto.Envelope
		if err := dec.Decode(&certReq); err != nil {
			peerErrCh <- err
			return
		}
		if certReq.LeafCertRequest == nil || certReq.LeafCertRequest.Host != "example.com" {
			peerErrCh <- fmt.Errorf("expected leaf cert request for example.com, got %#v", certReq)
			return
		}
		if err := enc.Encode(&helperproto.Envelope{
			ID: certReq.ID,
			LeafCertResponse: &helperproto.LeafCertResponse{
				CertPEM: certPEM,
				KeyPEM:  keyPEM,
			},
		}); err != nil {
			peerErrCh <- err
			return
		}

		var mitmReq helperproto.Envelope
		if err := dec.Decode(&mitmReq); err != nil {
			peerErrCh <- err
			return
		}
		if mitmReq.MITMRequest == nil {
			peerErrCh <- fmt.Errorf("expected MITM request, got %#v", mitmReq)
			return
		}
		if mitmReq.MITMRequest.Method != http.MethodGet || mitmReq.MITMRequest.Path != "/allowed" {
			peerErrCh <- fmt.Errorf("unexpected MITM request payload: %#v", mitmReq.MITMRequest)
			return
		}
		if err := enc.Encode(&helperproto.Envelope{
			ID: mitmReq.ID,
			MITMResponse: &helperproto.MITMResponse{
				StatusCode: http.StatusOK,
				Header:     http.Header{"X-Intercepted": []string{"yes"}},
				Body:       []byte("intercepted ok"),
			},
		}); err != nil {
			peerErrCh <- err
			return
		}

		peerErrCh <- nil
	}()

	server := httptest.NewServer(bridge.proxyHandler())
	defer server.Close()

	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			TLSClientConfig:   &tls.Config{RootCAs: caRoots},
			ForceAttemptHTTP2: false,
		},
	}

	resp, err := client.Get("https://example.com/allowed")
	if err != nil {
		t.Fatalf("client GET failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "intercepted ok" {
		t.Fatalf("unexpected body: %q", string(body))
	}
	if got := resp.Header.Get("X-Intercepted"); got != "yes" {
		t.Fatalf("unexpected header: %q", got)
	}

	select {
	case err := <-peerErrCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for MITM bridge peer")
	}

	cancel()
	_ = peerSide.Close()
	select {
	case err := <-readLoopErrCh:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected readLoop shutdown error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for readLoop to exit")
	}
}

func TestProxyHandlerMITMHTTP1ReturnsDeterministicFailure(t *testing.T) {
	bridgeSide, peerSide := net.Pipe()
	defer bridgeSide.Close()
	defer peerSide.Close()

	bridge := newBridge(bridgeSide, log.New(io.Discard, "", 0), "127.0.0.1:31111")
	bridge.mitmEnabled = true
	bridge.maxRequestBodyBytes = 1024

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readLoopErrCh := make(chan error, 1)
	go func() {
		readLoopErrCh <- bridge.readLoop(ctx)
	}()

	caRoots, certPEM, keyPEM := issueTestLeafCertPEM(t, "example.com")

	peerErrCh := make(chan error, 1)
	go func() {
		dec := gob.NewDecoder(peerSide)
		enc := gob.NewEncoder(peerSide)

		var connectReq helperproto.Envelope
		if err := dec.Decode(&connectReq); err != nil {
			peerErrCh <- err
			return
		}
		if err := enc.Encode(&helperproto.Envelope{
			ID: connectReq.ID,
			ConnectResponse: &helperproto.ConnectResponse{
				StatusCode: http.StatusOK,
			},
		}); err != nil {
			peerErrCh <- err
			return
		}

		var certReq helperproto.Envelope
		if err := dec.Decode(&certReq); err != nil {
			peerErrCh <- err
			return
		}
		if err := enc.Encode(&helperproto.Envelope{
			ID: certReq.ID,
			LeafCertResponse: &helperproto.LeafCertResponse{
				CertPEM: certPEM,
				KeyPEM:  keyPEM,
			},
		}); err != nil {
			peerErrCh <- err
			return
		}

		var mitmReq helperproto.Envelope
		if err := dec.Decode(&mitmReq); err != nil {
			peerErrCh <- err
			return
		}
		if err := enc.Encode(&helperproto.Envelope{
			ID: mitmReq.ID,
			MITMResponse: &helperproto.MITMResponse{
				StatusCode: http.StatusForbidden,
				Header:     http.Header{"Content-Type": []string{"text/plain"}},
				Body:       []byte("blocked by policy"),
			},
		}); err != nil {
			peerErrCh <- err
			return
		}

		peerErrCh <- nil
	}()

	server := httptest.NewServer(bridge.proxyHandler())
	defer server.Close()

	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			TLSClientConfig:   &tls.Config{RootCAs: caRoots},
			ForceAttemptHTTP2: false,
		},
	}

	resp, err := client.Get("https://example.com/blocked")
	if err != nil {
		t.Fatalf("client GET failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", resp.StatusCode)
	}

	select {
	case err := <-peerErrCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for MITM bridge peer")
	}

	cancel()
	_ = peerSide.Close()
	select {
	case err := <-readLoopErrCh:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected readLoop shutdown error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for readLoop to exit")
	}
}

func TestMITMHTTP2HandlesConcurrentStreams(t *testing.T) {
	bridgeSide, peerSide := net.Pipe()
	defer bridgeSide.Close()
	defer peerSide.Close()

	bridge := newBridge(bridgeSide, log.New(io.Discard, "", 0), "127.0.0.1:31111")
	bridge.mitmEnabled = true
	bridge.maxRequestBodyBytes = 1024

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readLoopErrCh := make(chan error, 1)
	go func() {
		readLoopErrCh <- bridge.readLoop(ctx)
	}()

	const streamCount = 8
	caRoots, certPEM, keyPEM := issueTestLeafCertPEM(t, "example.com")

	peerErrCh := make(chan error, 1)
	go func() {
		dec := gob.NewDecoder(peerSide)
		enc := gob.NewEncoder(peerSide)
		var sendMu sync.Mutex

		var connectReq helperproto.Envelope
		if err := dec.Decode(&connectReq); err != nil {
			peerErrCh <- err
			return
		}
		if connectReq.ConnectRequest == nil {
			peerErrCh <- fmt.Errorf("expected connect request, got %#v", connectReq)
			return
		}
		sendMu.Lock()
		err := enc.Encode(&helperproto.Envelope{
			ID: connectReq.ID,
			ConnectResponse: &helperproto.ConnectResponse{
				StatusCode: http.StatusOK,
			},
		})
		sendMu.Unlock()
		if err != nil {
			peerErrCh <- err
			return
		}

		var certReq helperproto.Envelope
		if err := dec.Decode(&certReq); err != nil {
			peerErrCh <- err
			return
		}
		if certReq.LeafCertRequest == nil {
			peerErrCh <- fmt.Errorf("expected leaf cert request, got %#v", certReq)
			return
		}
		sendMu.Lock()
		err = enc.Encode(&helperproto.Envelope{
			ID: certReq.ID,
			LeafCertResponse: &helperproto.LeafCertResponse{
				CertPEM: certPEM,
				KeyPEM:  keyPEM,
			},
		})
		sendMu.Unlock()
		if err != nil {
			peerErrCh <- err
			return
		}

		var wg sync.WaitGroup
		wg.Add(streamCount)
		for i := 0; i < streamCount; i++ {
			var mitmReq helperproto.Envelope
			if err := dec.Decode(&mitmReq); err != nil {
				peerErrCh <- err
				return
			}
			if mitmReq.MITMRequest == nil {
				peerErrCh <- fmt.Errorf("expected MITM request, got %#v", mitmReq)
				return
			}
			if mitmReq.MITMRequest.Proto != "HTTP/2.0" {
				peerErrCh <- fmt.Errorf("expected HTTP/2.0 request, got %#v", mitmReq.MITMRequest)
				return
			}

			id := mitmReq.ID
			path := mitmReq.MITMRequest.Path
			delay := time.Duration(streamCount-i) * 5 * time.Millisecond
			go func() {
				defer wg.Done()
				time.Sleep(delay)
				sendMu.Lock()
				defer sendMu.Unlock()
				_ = enc.Encode(&helperproto.Envelope{
					ID: id,
					MITMResponse: &helperproto.MITMResponse{
						StatusCode: http.StatusOK,
						Body:       []byte(path),
					},
				})
			}()
		}
		wg.Wait()
		peerErrCh <- nil
	}()

	server := httptest.NewServer(bridge.proxyHandler())
	defer server.Close()

	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		TLSClientConfig:   &tls.Config{RootCAs: caRoots},
		ForceAttemptHTTP2: true,
		MaxConnsPerHost:   1,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}

	errCh := make(chan error, streamCount)
	for i := 0; i < streamCount; i++ {
		i := i
		go func() {
			targetURL := fmt.Sprintf("https://example.com/stream-%d", i)
			resp, err := client.Get(targetURL)
			if err != nil {
				errCh <- err
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				errCh <- err
				return
			}
			if string(body) != fmt.Sprintf("/stream-%d", i) {
				errCh <- fmt.Errorf("unexpected body for stream %d: %q", i, string(body))
				return
			}
			errCh <- nil
		}()
	}

	for i := 0; i < streamCount; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}

	select {
	case err := <-peerErrCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HTTP/2 bridge peer")
	}

	cancel()
	_ = peerSide.Close()
	select {
	case err := <-readLoopErrCh:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected readLoop shutdown error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for readLoop to exit")
	}
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

func startTransparentRuntime(t *testing.T) (string, func()) {
	t.Helper()

	ready, shutdown := startTransparentRuntimeReady(t)
	return ready.DNSAddr, shutdown
}

func startTransparentRuntimeReady(t *testing.T) (*helperproto.Ready, func()) {
	t.Helper()

	bridgeSide, peerSide := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)

	go func() {
		errCh <- Run(ctx, Config{
			Bridge:      bridgeSide,
			TrafficMode: TrafficModeTransparent,
			DNSAddr:     "127.0.0.1:0",
			HTTPAddr:    "127.0.0.1:0",
			HTTPSAddr:   "127.0.0.1:0",
			Logger:      log.New(io.Discard, "", 0),
		})
	}()

	enc := gob.NewEncoder(peerSide)
	dec := gob.NewDecoder(peerSide)
	if err := enc.Encode(&helperproto.Envelope{
		ID: 1,
		Hello: &helperproto.Hello{
			ProtocolVersion: helperproto.ProtocolVersion,
			SandboxID:       "transparent-dns-test",
		},
	}); err != nil {
		t.Fatalf("send hello: %v", err)
	}

	var ready helperproto.Envelope
	if err := dec.Decode(&ready); err != nil {
		t.Fatalf("read ready: %v", err)
	}
	if ready.Ready == nil {
		t.Fatalf("expected ready response, got %#v", ready)
	}
	if ready.Ready.DNSAddr == "" {
		t.Fatal("expected transparent runtime to report a DNS address")
	}
	if ready.Ready.HTTPAddr == "" {
		t.Fatal("expected transparent runtime to report an HTTP address")
	}

	shutdown := func() {
		cancel()
		_ = peerSide.Close()
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
				t.Fatalf("unexpected transparent runtime shutdown error: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for transparent runtime to exit")
		}
	}

	return ready.Ready, shutdown
}

func exchangeTransparentDNS(t *testing.T, network, addr string, queryType dnsmessage.Type) dnsmessage.Message {
	t.Helper()

	query := packTransparentDNSQuery(t, queryType)

	switch network {
	case "udp":
		return exchangeTransparentDNSUDP(t, addr, query)
	case "tcp":
		return exchangeTransparentDNSTCP(t, addr, query)
	default:
		t.Fatalf("unsupported DNS transport %q", network)
		return dnsmessage.Message{}
	}
}

func packTransparentDNSQuery(t *testing.T, queryType dnsmessage.Type) []byte {
	t.Helper()

	name, err := dnsmessage.NewName("example.com.")
	if err != nil {
		t.Fatalf("construct DNS name: %v", err)
	}

	query := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 7,
			RecursionDesired:   true,
			Response:           false,
			Authoritative:      false,
			RecursionAvailable: false,
		},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  queryType,
			Class: dnsmessage.ClassINET,
		}},
	}

	payload, err := query.Pack()
	if err != nil {
		t.Fatalf("pack DNS query: %v", err)
	}

	return payload
}

func exchangeTransparentDNSUDP(t *testing.T, addr string, query []byte) dnsmessage.Message {
	t.Helper()

	conn, err := net.DialTimeout("udp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial UDP DNS listener: %v", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set UDP deadline: %v", err)
	}
	if _, err := conn.Write(query); err != nil {
		t.Fatalf("write UDP DNS query: %v", err)
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read UDP DNS response: %v", err)
	}

	return unpackTransparentDNSResponse(t, buf[:n])
}

func exchangeTransparentDNSTCP(t *testing.T, addr string, query []byte) dnsmessage.Message {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial TCP DNS listener: %v", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set TCP deadline: %v", err)
	}

	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write TCP DNS query: %v", err)
	}

	var lengthBuf [2]byte
	if _, err := io.ReadFull(conn, lengthBuf[:]); err != nil {
		t.Fatalf("read TCP DNS response length: %v", err)
	}
	responseLen := int(binary.BigEndian.Uint16(lengthBuf[:]))
	response := make([]byte, responseLen)
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("read TCP DNS response: %v", err)
	}

	return unpackTransparentDNSResponse(t, response)
}

func unpackTransparentDNSResponse(t *testing.T, payload []byte) dnsmessage.Message {
	t.Helper()

	var response dnsmessage.Message
	if err := response.Unpack(payload); err != nil {
		t.Fatalf("unpack DNS response: %v", err)
	}

	return response
}

func issueTestLeafCertPEM(t *testing.T, host string) (*x509.CertPool, []byte, []byte) {
	t.Helper()

	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test mitm ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leafPub, leafPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, leafPub, caPriv)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafPriv)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	leafKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER})

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("append CA PEM to roots")
	}
	return roots, leafPEM, leafKeyPEM
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

type testBridge struct{}

func newTestBridge() io.ReadWriteCloser {
	return testBridge{}
}

func (testBridge) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (testBridge) Write(p []byte) (int, error) {
	return len(p), nil
}

func (testBridge) Close() error {
	return nil
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
