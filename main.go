package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const bridgeFD = 3

type config struct {
	allowHostRegex []*regexp.Regexp
}

type regexListFlag struct {
	values []string
}

func (r *regexListFlag) String() string {
	return fmt.Sprint(r.values)
}

func (r *regexListFlag) Set(value string) error {
	r.values = append(r.values, value)
	return nil
}

func main() {
	log.SetFlags(0)
	if len(os.Args) > 1 && os.Args[1] == "child-proxy" {
		if err := runChildProxy(); err != nil {
			log.Fatal(err)
		}
		return
	}

	cfg, err := parseConfig(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}

	if err := runParent(cfg); err != nil {
		log.Fatal(err)
	}
}

func parseConfig(args []string) (config, error) {
	fs := flag.NewFlagSet("bwrap-go", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var allowHostRegex regexListFlag
	fs.Var(&allowHostRegex, "allow-host-regex", "allow outbound requests whose req.URL.Hostname() matches the regex; repeatable")

	if err := fs.Parse(args); err != nil {
		return config{}, err
	}

	cfg := config{}
	for _, expr := range allowHostRegex.values {
		re, err := regexp.Compile(expr)
		if err != nil {
			return config{}, fmt.Errorf("compile --allow-host-regex %q: %w", expr, err)
		}
		cfg.allowHostRegex = append(cfg.allowHostRegex, re)
	}
	return cfg, nil
}

func runParent(cfg config) error {
	root, err := stageSandboxRoot()
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)

	socketPair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("socketpair: %w", err)
	}

	parentSocket := os.NewFile(uintptr(socketPair[0]), "parent-proxy")
	childSocket := os.NewFile(uintptr(socketPair[1]), "child-proxy")
	defer parentSocket.Close()

	cmd := exec.Command("bwrap", buildBwrapArgs(root)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{childSocket}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start bwrap: %w", err)
	}
	childSocket.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := net.FileConn(parentSocket)
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		if err := serveForwardBridge(conn, cfg); err != nil && !errors.Is(err, io.EOF) {
			errCh <- err
		}
	}()

	log.Printf("sandbox root: %s", root)
	if len(cfg.allowHostRegex) == 0 {
		log.Printf("host allowlist: disabled")
	} else {
		for _, re := range cfg.allowHostRegex {
			log.Printf("host allowlist: %s", re.String())
		}
	}

	waitErr := cmd.Wait()

	select {
	case serveErr := <-errCh:
		if serveErr != nil {
			return fmt.Errorf("proxy serve: %w", serveErr)
		}
	default:
	}

	if waitErr != nil {
		return fmt.Errorf("sandbox command failed: %w", waitErr)
	}
	return nil
}

func runChildProxy() error {
	connFile := os.NewFile(uintptr(bridgeFD), "parent-proxy")
	conn, err := net.FileConn(connFile)
	if err != nil {
		return fmt.Errorf("bridge connection: %w", err)
	}
	if err := connFile.Close(); err != nil {
		return fmt.Errorf("close inherited bridge fd wrapper: %w", err)
	}
	if err := setConnCloseOnExec(conn); err != nil {
		return err
	}
	defer conn.Close()

	server := &http.Server{
		Handler:           newProxyHandler(newBridgeRoundTripper(conn)),
		ReadHeaderTimeout: 5 * time.Second,
	}
	listener, err := net.Listen("tcp", proxyBind)
	if err != nil {
		return fmt.Errorf("listen %s: %w", proxyBind, err)
	}
	defer listener.Close()

	errCh := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	curl := exec.Command(curlBinary, "-v", curlTarget)
	curl.Stdout = os.Stdout
	curl.Stderr = os.Stderr
	curl.Env = []string{
		"PATH=/usr/bin",
		"HTTP_PROXY=" + proxyURL(),
		"http_proxy=" + proxyURL(),
	}

	log.Printf("child proxy listening on %s", proxyBind)
	waitErr := curl.Run()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)

	select {
	case serveErr := <-errCh:
		if serveErr != nil {
			return fmt.Errorf("child proxy serve: %w", serveErr)
		}
	default:
	}

	if waitErr != nil {
		return fmt.Errorf("sandboxed curl failed: %w", waitErr)
	}
	return nil
}

func serveForwardBridge(conn net.Conn, cfg config) error {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil

	bridge := newBridgeRoundTripper(conn)
	for {
		var req forwardedRequest
		if err := bridge.dec.Decode(&req); err != nil {
			return err
		}

		respPayload, err := forwardRequest(transport, req, cfg)
		if err != nil {
			respPayload = forwardedResponse{StatusCode: http.StatusBadGateway, Error: err.Error()}
		}
		if err := bridge.enc.Encode(&respPayload); err != nil {
			return err
		}
	}
}

func setConnCloseOnExec(conn net.Conn) error {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return errors.New("bridge connection does not support SyscallConn")
	}

	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("bridge SyscallConn: %w", err)
	}

	if err := rawConn.Control(func(fd uintptr) {
		unix.CloseOnExec(int(fd))
	}); err != nil {
		return fmt.Errorf("set bridge CLOEXEC: %w", err)
	}
	return nil
}

func forwardRequest(transport *http.Transport, req forwardedRequest, cfg config) (forwardedResponse, error) {
	outReq, err := http.NewRequest(req.Method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		return forwardedResponse{}, err
	}
	outReq.Header = req.Header.Clone()

	if err := checkHostAllowed(outReq.URL.Hostname(), cfg.allowHostRegex); err != nil {
		log.Printf("proxy deny: %v", err)
		return forwardedResponse{
			StatusCode: http.StatusForbidden,
			Header:     http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
			Body:       []byte(err.Error() + "\n"),
			Error:      err.Error(),
		}, nil
	}

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		return forwardedResponse{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return forwardedResponse{}, err
	}

	return forwardedResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       body,
	}, nil
}

func checkHostAllowed(hostname string, allowlist []*regexp.Regexp) error {
	if hostname == "" {
		return errors.New("empty hostname is not allowed")
	}
	if len(allowlist) == 0 {
		return nil
	}
	for _, re := range allowlist {
		if re.MatchString(hostname) {
			return nil
		}
	}
	return fmt.Errorf("hostname %q is not allowed by proxy policy", hostname)
}
