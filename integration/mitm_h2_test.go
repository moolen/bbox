package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/moolen/bbox"
)

const h2ClientSource = `package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type result struct {
	WarmupProto       string   ` + "`json:\"warmup_proto\"`" + `
	Protocols         []string ` + "`json:\"protocols\"`" + `
	Bodies            []string ` + "`json:\"bodies\"`" + `
	UniqueConnections int      ` + "`json:\"unique_connections\"`" + `
	DurationMillis    int64    ` + "`json:\"duration_millis\"`" + `
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "usage: %s <base-url> <count> <proxy-url>\n", os.Args[0])
		os.Exit(2)
	}

	baseURL := strings.TrimRight(os.Args[1], "/")
	count, err := strconv.Atoi(os.Args[2])
	if err != nil || count <= 0 {
		fmt.Fprintf(os.Stderr, "invalid count %q\n", os.Args[2])
		os.Exit(2)
	}
	proxyURL, err := url.Parse(os.Args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid proxy url %q: %v\n", os.Args[3], err)
		os.Exit(2)
	}

	transport := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return proxyURL, nil
		},
		ForceAttemptHTTP2:   true,
		MaxConnsPerHost:     1,
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
	}

	var mu sync.Mutex
	connIDs := make(map[string]struct{})

	doGet := func(url string) (string, string, error) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		if err != nil {
			return "", "", err
		}
		trace := &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				mu.Lock()
				connIDs[fmt.Sprintf("%p", info.Conn)] = struct{}{}
				mu.Unlock()
			},
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

		resp, err := client.Do(req)
		if err != nil {
			return "", "", err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", "", err
		}
		if resp.StatusCode != http.StatusOK {
			return "", "", fmt.Errorf("unexpected status %d body=%s", resp.StatusCode, string(body))
		}
		return resp.Proto, string(body), nil
	}

	warmupProto, warmupBody, err := doGet(baseURL + "/warmup")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if warmupBody != "warmup" {
		fmt.Fprintf(os.Stderr, "unexpected warmup body %q\n", warmupBody)
		os.Exit(1)
	}

	start := time.Now()
	protocols := make([]string, count)
	bodies := make([]string, count)
	errCh := make(chan error, count)
	var wg sync.WaitGroup
	wg.Add(count)
	for i := 0; i < count; i++ {
		i := i
		go func() {
			defer wg.Done()
			proto, body, err := doGet(fmt.Sprintf("%s/stream/%d", baseURL, i))
			if err != nil {
				errCh <- err
				return
			}
			protocols[i] = proto
			bodies[i] = body
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	if err := json.NewEncoder(os.Stdout).Encode(result{
		WarmupProto:       warmupProto,
		Protocols:         protocols,
		Bodies:            bodies,
		UniqueConnections: len(connIDs),
		DurationMillis:    time.Since(start).Milliseconds(),
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
`

type h2ClientResult struct {
	WarmupProto       string   `json:"warmup_proto"`
	Protocols         []string `json:"protocols"`
	Bodies            []string `json:"bodies"`
	UniqueConnections int      `json:"unique_connections"`
	DurationMillis    int64    `json:"duration_millis"`
}

func TestSandboxMITMHTTP2ConcurrentStreams(t *testing.T) {
	requireSandboxPrereqs(t)

	server := startTrustedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/warmup":
			_, _ = w.Write([]byte("warmup"))
		case len(r.URL.Path) > len("/stream/") && r.URL.Path[:8] == "/stream/":
			time.Sleep(150 * time.Millisecond)
			_, _ = w.Write([]byte(r.URL.Path))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	trustHTTPSServer(t, server)

	clientBinary := buildStaticTestClient(t, "h2-client", h2ClientSource)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{
		MITM: bbox.MITMOptions{
			Enabled:             true,
			MaxRequestBodyBytes: 1024,
		},
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
		Name:     "mitm-h2",
		Binaries: []string{clientBinary},
		Mounts: []bbox.Mount{
			{Source: filepath.Dir(clientBinary), Target: "/workspace", ReadOnly: true},
		},
		Policy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^127[.]0[.]0[.]1$`},
			AllowHTTPMethods:  []string{"GET"},
			AllowConnect:      true,
			AllowConnectPorts: []string{mustPortForServer(t, server)},
			AllowPathPatterns: []string{`^/warmup$`, `^/stream/[0-9]+$`},
		},
	})
	if err != nil {
		t.Fatalf("create h2 sandbox: %v", err)
	}
	defer func() {
		if err := sandbox.Close(); err != nil {
			t.Fatalf("close h2 sandbox: %v", err)
		}
	}()

	result, err := sandbox.Run(ctx, []string{
		"/workspace/" + filepath.Base(clientBinary),
		server.URL,
		"8",
		sandbox.ProxyURL(),
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("run h2 client: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("expected h2 client to succeed, exit=%d stdout=%q stderr=%q", result.ExitCode, string(result.Stdout), string(result.Stderr))
	}

	var decoded h2ClientResult
	if err := json.Unmarshal(result.Stdout, &decoded); err != nil {
		t.Fatalf("decode h2 client result: %v; stdout=%q", err, string(result.Stdout))
	}
	if decoded.WarmupProto != "HTTP/2.0" {
		t.Fatalf("expected warmup request to negotiate HTTP/2, got %q", decoded.WarmupProto)
	}
	if decoded.UniqueConnections != 1 {
		t.Fatalf("expected a single intercepted client connection, got %d", decoded.UniqueConnections)
	}
	if len(decoded.Protocols) != 8 {
		t.Fatalf("expected 8 protocols, got %d", len(decoded.Protocols))
	}
	for i, proto := range decoded.Protocols {
		if proto != "HTTP/2.0" {
			t.Fatalf("expected stream %d to use HTTP/2.0, got %q", i, proto)
		}
		wantBody := "/stream/" + strconv.Itoa(i)
		if decoded.Bodies[i] != wantBody {
			t.Fatalf("unexpected body for stream %d: got %q want %q", i, decoded.Bodies[i], wantBody)
		}
	}
	if decoded.DurationMillis <= 0 {
		t.Fatalf("expected positive duration, got %d", decoded.DurationMillis)
	}
	if decoded.DurationMillis > 900 {
		t.Fatalf("expected concurrent streams to finish well under serialized time, got %dms", decoded.DurationMillis)
	}
}
