package bbox

import (
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
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
	ctx       context.Context
	cancel    context.CancelFunc

	sendMu sync.Mutex

	readyCh   chan helperReady
	readyOnce sync.Once
	loopDone  chan error
	nextID    atomic.Uint64

	execMu     sync.Mutex
	currentMu  sync.Mutex
	currentRun *runSession

	tunnelMu       sync.Mutex
	tunnels        map[uint64]*hostTunnel
	pendingTunnels map[uint64]*hostTunnel

	closeOnce sync.Once
}

func newHelperClient(manager *ProxyManager, sandboxID string, conn io.ReadWriteCloser) *helperClient {
	clientCtx, cancel := context.WithCancel(context.Background())
	return &helperClient{
		sandboxID:      sandboxID,
		manager:        manager,
		conn:           conn,
		enc:            gob.NewEncoder(conn),
		dec:            gob.NewDecoder(conn),
		ctx:            clientCtx,
		cancel:         cancel,
		readyCh:        make(chan helperReady, 1),
		loopDone:       make(chan error, 1),
		tunnels:        make(map[uint64]*hostTunnel),
		pendingTunnels: make(map[uint64]*hostTunnel),
	}
}

func (c *helperClient) Start(ctx context.Context) (string, error) {
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
		return "", fmt.Errorf("send helper hello: %w", err)
	}

	select {
	case ready := <-c.readyCh:
		if ready.err != nil {
			return "", ready.err
		}
		if ready.proxyAddr != "" {
			return ready.proxyAddr, nil
		}
		if ready.hasTransparentListeners() {
			return "", nil
		}
		return "", errors.New("helper did not report proxy or transparent listener readiness")
	case err := <-c.loopDone:
		if err == nil {
			return "", errors.New("helper exited before signaling readiness")
		}
		return "", fmt.Errorf("wait for helper readiness: %w", err)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (c *helperClient) Run(ctx context.Context, argv []string, opts RunOptions) (*RunResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	c.execMu.Lock()
	defer c.execMu.Unlock()

	state := newRunSession(opts.Stdout, opts.Stderr)
	if err := c.installRunSession(state); err != nil {
		return nil, err
	}

	interactive := opts.Interactive || opts.Stdin != nil || opts.Stdout != nil || opts.Stderr != nil || opts.Terminal || opts.Resize != nil

	var initialSize *helperproto.TerminalSize
	if opts.TerminalSize.Rows > 0 || opts.TerminalSize.Cols > 0 {
		initialSize = &helperproto.TerminalSize{
			Rows: opts.TerminalSize.Rows,
			Cols: opts.TerminalSize.Cols,
		}
	}

	env := helperproto.Envelope{
		ID: c.nextID.Add(1),
		ExecRequest: &helperproto.ExecRequest{
			Argv:        append([]string(nil), argv...),
			Env:         append([]string(nil), opts.Env...),
			WorkDir:     opts.WorkDir,
			Interactive: interactive,
			Terminal:    opts.Terminal,
			InitialSize: initialSize,
		},
	}
	if err := c.send(env); err != nil {
		runErr := fmt.Errorf("send exec request: %w", err)
		c.failCurrentRun(runErr)
		return nil, runErr
	}

	if interactive {
		if opts.Stdin != nil {
			go c.pumpRunInput(env.ID, opts.Stdin)
		}
		if opts.Resize != nil {
			go c.pumpRunResize(env.ID, opts.Resize)
		}
	}

	select {
	case outcome := <-state.resultCh:
		return outcome.result, outcome.err
	case err := <-c.loopDone:
		if err == nil {
			err = errors.New("helper bridge closed")
		}
		state.Finish(nil, err)
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *helperClient) Close() error {
	var closeErr error

	c.closeOnce.Do(func() {
		c.cancel()
		c.shutdownTunnels()
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

func (c *helperClient) send(env helperproto.Envelope) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return c.enc.Encode(&env)
}
