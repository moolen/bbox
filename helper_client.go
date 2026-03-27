package bbox

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/moolen/bbox/internal/helperproto"
)

type helperClient struct {
	sandboxID string
	manager   *ProxyManager
	conn      io.ReadWriteCloser
	enc       *gob.Encoder
	dec       *gob.Decoder

	sendMu sync.Mutex

	readyCh   chan helperReady
	readyOnce sync.Once
	loopDone  chan error
	nextID    atomic.Uint64

	execMu     sync.Mutex
	currentMu  sync.Mutex
	currentRun *runState

	closeOnce sync.Once
}

type helperReady struct {
	proxyAddr string
	err       error
}

type runState struct {
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	resultCh chan runOutcome
}

type runOutcome struct {
	result *RunResult
	err    error
}

func newHelperClient(manager *ProxyManager, sandboxID string, conn io.ReadWriteCloser) *helperClient {
	return &helperClient{
		sandboxID: sandboxID,
		manager:   manager,
		conn:      conn,
		enc:       gob.NewEncoder(conn),
		dec:       gob.NewDecoder(conn),
		readyCh:   make(chan helperReady, 1),
		loopDone:  make(chan error, 1),
	}
}

func (c *helperClient) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	go func() {
		c.loopDone <- c.readLoop()
	}()

	if err := c.send(helperproto.Envelope{
		ID: c.nextID.Add(1),
		Hello: &helperproto.Hello{
			ProtocolVersion: helperproto.ProtocolVersion,
			SandboxID:       c.sandboxID,
		},
	}); err != nil {
		return fmt.Errorf("send helper hello: %w", err)
	}

	select {
	case ready := <-c.readyCh:
		if ready.err != nil {
			return ready.err
		}
		if ready.proxyAddr == "" {
			return errors.New("helper did not report a proxy address")
		}
		return nil
	case err := <-c.loopDone:
		if err == nil {
			return errors.New("helper exited before signaling readiness")
		}
		return fmt.Errorf("wait for helper readiness: %w", err)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *helperClient) Run(ctx context.Context, argv []string, opts RunOptions) (*RunResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	c.execMu.Lock()
	defer c.execMu.Unlock()

	state := &runState{
		resultCh: make(chan runOutcome, 1),
	}

	c.currentMu.Lock()
	if c.currentRun != nil {
		c.currentMu.Unlock()
		return nil, errors.New("another command is already running")
	}
	c.currentRun = state
	c.currentMu.Unlock()

	env := helperproto.Envelope{
		ID: c.nextID.Add(1),
		ExecRequest: &helperproto.ExecRequest{
			Argv:    append([]string(nil), argv...),
			Env:     append([]string(nil), opts.Env...),
			WorkDir: opts.WorkDir,
		},
	}
	if err := c.send(env); err != nil {
		c.finishRun(state, nil, fmt.Errorf("send exec request: %w", err))
		return nil, fmt.Errorf("send exec request: %w", err)
	}

	select {
	case outcome := <-state.resultCh:
		return outcome.result, outcome.err
	case err := <-c.loopDone:
		if err == nil {
			err = errors.New("helper bridge closed")
		}
		c.finishRun(state, nil, err)
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *helperClient) Close() error {
	var closeErr error

	c.closeOnce.Do(func() {
		closeErr = c.conn.Close()
		select {
		case err := <-c.loopDone:
			if normalized := normalizeLoopCloseError(err); normalized != nil {
				closeErr = errors.Join(closeErr, normalized)
			}
		default:
		}
	})

	return closeErr
}

func (c *helperClient) readLoop() error {
	for {
		var env helperproto.Envelope
		if err := c.dec.Decode(&env); err != nil {
			c.notifyReady("", err)
			c.failCurrentRun(err)
			return err
		}

		switch {
		case env.Ready != nil:
			if env.Ready.ProtocolVersion != helperproto.ProtocolVersion {
				err := fmt.Errorf("unexpected helper protocol version %d", env.Ready.ProtocolVersion)
				c.notifyReady("", err)
				c.failCurrentRun(err)
				return err
			}
			c.notifyReady(env.Ready.ProxyAddr, nil)
		case env.ProxyRequest != nil:
			req := *env.ProxyRequest
			go c.handleProxyRequest(env.ID, req)
		case env.StreamFrame != nil:
			c.handleStream(*env.StreamFrame)
		case env.ExecResult != nil:
			c.handleExecResult(*env.ExecResult)
		}
	}
}

func (c *helperClient) notifyReady(proxyAddr string, err error) {
	c.readyOnce.Do(func() {
		c.readyCh <- helperReady{proxyAddr: proxyAddr, err: err}
	})
}

func (c *helperClient) handleProxyRequest(id uint64, req helperproto.ProxyRequest) {
	response := c.manager.handleProxyRequest(context.Background(), c.sandboxID, req)
	if err := c.send(helperproto.Envelope{
		ID:            id,
		ProxyResponse: response,
	}); err != nil {
		c.failCurrentRun(err)
	}
}

func (c *helperClient) handleStream(frame helperproto.StreamFrame) {
	c.currentMu.Lock()
	defer c.currentMu.Unlock()

	if c.currentRun == nil {
		return
	}

	switch frame.Stream {
	case helperproto.StreamStdout:
		_, _ = c.currentRun.stdout.Write(frame.Data)
	case helperproto.StreamStderr:
		_, _ = c.currentRun.stderr.Write(frame.Data)
	}
}

func (c *helperClient) handleExecResult(result helperproto.ExecResult) {
	c.currentMu.Lock()
	state := c.currentRun
	c.currentRun = nil
	c.currentMu.Unlock()

	if state == nil {
		return
	}

	stderr := append([]byte(nil), state.stderr.Bytes()...)
	if len(result.Stderr) > 0 {
		stderr = append(stderr, result.Stderr...)
	}

	state.resultCh <- runOutcome{
		result: &RunResult{
			ExitCode: result.ExitCode,
			Stdout:   append([]byte(nil), state.stdout.Bytes()...),
			Stderr:   stderr,
		},
	}
}

func (c *helperClient) failCurrentRun(err error) {
	c.currentMu.Lock()
	state := c.currentRun
	c.currentRun = nil
	c.currentMu.Unlock()

	if state == nil {
		return
	}

	c.finishRun(state, nil, err)
}

func (c *helperClient) finishRun(state *runState, result *RunResult, err error) {
	if state == nil {
		return
	}

	select {
	case state.resultCh <- runOutcome{result: result, err: err}:
	default:
	}
}

func normalizeLoopCloseError(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (c *helperClient) send(env helperproto.Envelope) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return c.enc.Encode(&env)
}
