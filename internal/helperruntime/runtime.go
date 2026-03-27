package helperruntime

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/moolen/bbox/internal/helperproto"
)

const DefaultProxyAddr = "127.0.0.1:31111"

type Config struct {
	Bridge    io.ReadWriteCloser
	ProxyAddr string
	Logger    *log.Logger
}

func OpenBridgeFromFD(fd int) (io.ReadWriteCloser, error) {
	if fd < 0 {
		return nil, fmt.Errorf("bridge fd must be non-negative")
	}

	syscall.CloseOnExec(fd)

	file := os.NewFile(uintptr(fd), fmt.Sprintf("bbox-helper-bridge-%d", fd))
	if file == nil {
		return nil, fmt.Errorf("bridge fd %d is invalid", fd)
	}

	return file, nil
}

func Run(ctx context.Context, cfg Config) error {
	if cfg.Bridge == nil {
		return fmt.Errorf("bridge is required")
	}
	if cfg.ProxyAddr == "" {
		cfg.ProxyAddr = DefaultProxyAddr
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(io.Discard, "", 0)
	}

	listener, err := net.Listen("tcp", cfg.ProxyAddr)
	if err != nil {
		return fmt.Errorf("listen on proxy address %q: %w", cfg.ProxyAddr, err)
	}
	defer listener.Close()

	bridge := newBridge(cfg.Bridge, cfg.Logger, listener.Addr().String())

	server := &http.Server{
		Handler: bridge.proxyHandler(),
	}

	errCh := make(chan error, 2)

	go func() {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = server.Shutdown(shutdownCtx)
		_ = cfg.Bridge.Close()
	}()

	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("serve proxy listener: %w", err)
		}
	}()

	go func() {
		errCh <- bridge.readLoop(ctx)
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}

type bridge struct {
	conn      io.ReadWriteCloser
	enc       *gob.Encoder
	dec       *gob.Decoder
	logger    *log.Logger
	proxyAddr string
	sendMu    sync.Mutex
	pending   map[uint64]chan helperproto.Envelope
	pendMu    sync.Mutex
	nextID    atomic.Uint64
	execMu    sync.Mutex
}

func newBridge(conn io.ReadWriteCloser, logger *log.Logger, proxyAddr string) *bridge {
	return &bridge{
		conn:      conn,
		enc:       gob.NewEncoder(conn),
		dec:       gob.NewDecoder(conn),
		logger:    logger,
		proxyAddr: proxyAddr,
		pending:   make(map[uint64]chan helperproto.Envelope),
	}
}

func (b *bridge) readLoop(ctx context.Context) error {
	for {
		var env helperproto.Envelope
		if err := b.dec.Decode(&env); err != nil {
			return err
		}

		switch {
		case env.Hello != nil:
			if err := b.handleHello(env); err != nil {
				return err
			}
		case env.ProxyResponse != nil:
			b.deliver(env)
		case env.ExecRequest != nil:
			go b.handleExec(ctx, env.ID, *env.ExecRequest)
		default:
			b.logger.Printf("ignoring unsupported helper envelope kind %q", env.Kind())
		}
	}
}

func (b *bridge) handleHello(env helperproto.Envelope) error {
	if env.Hello.ProtocolVersion != helperproto.ProtocolVersion {
		return fmt.Errorf("unsupported protocol version %d", env.Hello.ProtocolVersion)
	}

	return b.send(helperproto.Envelope{
		ID: env.ID,
		Ready: &helperproto.Ready{
			ProtocolVersion: helperproto.ProtocolVersion,
			ProxyAddr:       b.proxyAddr,
		},
	})
}

func (b *bridge) proxyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		outReq, err := rewriteProxyRequest(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var body []byte
		if outReq.Body != nil {
			body, err = io.ReadAll(outReq.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
		}

		response, err := b.proxyRoundTrip(req.Context(), helperproto.ProxyRequest{
			Method: outReq.Method,
			URL:    outReq.URL.String(),
			Header: outReq.Header.Clone(),
			Body:   body,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		copyHeader(w.Header(), response.Header)
		w.WriteHeader(response.StatusCode)
		if _, err := io.Copy(w, bytes.NewReader(response.Body)); err != nil {
			b.logger.Printf("copy proxied response body: %v", err)
		}
	})
}

func (b *bridge) proxyRoundTrip(ctx context.Context, req helperproto.ProxyRequest) (*helperproto.ProxyResponse, error) {
	id := b.nextID.Add(1)
	ch := make(chan helperproto.Envelope, 1)

	b.pendMu.Lock()
	b.pending[id] = ch
	b.pendMu.Unlock()

	defer func() {
		b.pendMu.Lock()
		delete(b.pending, id)
		b.pendMu.Unlock()
	}()

	if err := b.send(helperproto.Envelope{
		ID:           id,
		ProxyRequest: &req,
	}); err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case env := <-ch:
		if env.ProxyResponse == nil {
			return nil, fmt.Errorf("bridge response %d did not contain a proxy response", id)
		}
		if env.ProxyResponse.Error != "" {
			return nil, errors.New(env.ProxyResponse.Error)
		}
		return env.ProxyResponse, nil
	}
}

func (b *bridge) deliver(env helperproto.Envelope) {
	b.pendMu.Lock()
	ch := b.pending[env.ID]
	b.pendMu.Unlock()
	if ch == nil {
		b.logger.Printf("dropping bridge response for unknown request %d", env.ID)
		return
	}

	select {
	case ch <- env:
	default:
		b.logger.Printf("dropping duplicate bridge response for request %d", env.ID)
	}
}

func (b *bridge) handleExec(ctx context.Context, id uint64, req helperproto.ExecRequest) {
	b.execMu.Lock()
	defer b.execMu.Unlock()

	if len(req.Argv) == 0 {
		_ = b.send(helperproto.Envelope{
			ID: id,
			ExecResult: &helperproto.ExecResult{
				ExitCode: -1,
				Stderr:   []byte("argv is required"),
				Error:    "argv is required",
			},
		})
		return
	}

	cmd := exec.CommandContext(ctx, req.Argv[0], req.Argv[1:]...)
	cmd.Env = append([]string(nil), req.Env...)
	cmd.Dir = req.WorkDir

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		b.sendExecError(id, err)
		return
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		b.sendExecError(id, err)
		return
	}

	if err := cmd.Start(); err != nil {
		b.sendExecError(id, err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		b.streamOutput(id, helperproto.StreamStdout, stdout)
	}()

	go func() {
		defer wg.Done()
		b.streamOutput(id, helperproto.StreamStderr, stderr)
	}()

	waitErr := cmd.Wait()
	wg.Wait()

	result := &helperproto.ExecResult{}
	if waitErr == nil {
		result.ExitCode = 0
	} else {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
			result.Stderr = []byte(waitErr.Error())
			result.Error = waitErr.Error()
		}
	}

	if err := b.send(helperproto.Envelope{
		ID:         id,
		ExecResult: result,
	}); err != nil {
		b.logger.Printf("send exec result: %v", err)
	}
}

func (b *bridge) sendExecError(id uint64, err error) {
	if sendErr := b.send(helperproto.Envelope{
		ID: id,
		ExecResult: &helperproto.ExecResult{
			ExitCode: -1,
			Stderr:   []byte(err.Error()),
			Error:    err.Error(),
		},
	}); sendErr != nil {
		b.logger.Printf("send exec error: %v", sendErr)
	}
}

func (b *bridge) streamOutput(id uint64, stream helperproto.StreamType, src io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if sendErr := b.send(helperproto.Envelope{
				ID: id,
				StreamFrame: &helperproto.StreamFrame{
					Stream: stream,
					Data:   append([]byte(nil), buf[:n]...),
				},
			}); sendErr != nil {
				b.logger.Printf("send %s frame: %v", stream, sendErr)
				return
			}
		}
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			b.logger.Printf("read %s stream: %v", stream, err)
			return
		}
	}
}

func (b *bridge) send(env helperproto.Envelope) error {
	b.sendMu.Lock()
	defer b.sendMu.Unlock()
	return b.enc.Encode(&env)
}

func rewriteProxyRequest(req *http.Request) (*http.Request, error) {
	if req.Method == http.MethodConnect {
		return nil, errors.New("CONNECT is not implemented in the helper runtime")
	}
	if req.URL == nil || req.URL.Scheme == "" || req.URL.Host == "" {
		return nil, errors.New("proxy request must use an absolute URL")
	}

	out := req.Clone(req.Context())
	urlCopy := *req.URL
	out.URL = &urlCopy
	out.RequestURI = ""
	out.Host = out.URL.Host
	out.Header = req.Header.Clone()
	out.Header.Del("Proxy-Connection")

	return out, nil
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
