package bridge

import (
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"

	"github.com/moolen/bbox/internal/helperproto"
)

type RuntimeBridge struct {
	conn      io.ReadWriteCloser
	enc       *gob.Encoder
	dec       *gob.Decoder
	logger    *log.Logger
	proxyAddr string
	dnsAddr   string
	httpAddr  string
	httpsAddr string

	sendMu   sync.Mutex
	pending  map[uint64]chan helperproto.Envelope
	pendMu   sync.Mutex
	tunnels  map[uint64]*tunnelDelivery
	tunnelMu sync.Mutex
	nextID   atomic.Uint64

	onExecRequest func(context.Context, uint64, helperproto.ExecRequest)
	onExecInput   func(helperproto.ExecInput)
}

type tunnelDelivery struct {
	ch     chan helperproto.Envelope
	closed chan struct{}
}

type TunnelRelayResult struct {
	SendClose bool
	Write     bool
	Err       error
	Terminal  bool
}

func New(conn io.ReadWriteCloser, logger *log.Logger, proxyAddr string) *RuntimeBridge {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	return &RuntimeBridge{
		conn:      conn,
		enc:       gob.NewEncoder(conn),
		dec:       gob.NewDecoder(conn),
		logger:    logger,
		proxyAddr: proxyAddr,
		pending:   make(map[uint64]chan helperproto.Envelope),
		tunnels:   make(map[uint64]*tunnelDelivery),
	}
}

func (b *RuntimeBridge) SetReadyAddrs(dnsAddr, httpAddr, httpsAddr string) {
	b.dnsAddr = dnsAddr
	b.httpAddr = httpAddr
	b.httpsAddr = httpsAddr
}

func (b *RuntimeBridge) SetExecHandlers(
	onExecRequest func(context.Context, uint64, helperproto.ExecRequest),
	onExecInput func(helperproto.ExecInput),
) {
	b.onExecRequest = onExecRequest
	b.onExecInput = onExecInput
}

func (b *RuntimeBridge) ReadLoop(ctx context.Context) error {
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
		case env.ProxyResponse != nil, env.MITMResponse != nil, env.LeafCertResponse != nil:
			b.deliver(env)
		case env.ConnectResponse != nil:
			b.deliver(env)
		case env.TunnelFrame != nil, env.TunnelClose != nil:
			b.DeliverTunnel(env)
		case env.ExecRequest != nil:
			if b.onExecRequest == nil {
				b.logger.Printf("ignoring unsupported helper envelope kind %q", env.Kind())
				continue
			}
			go b.onExecRequest(ctx, env.ID, *env.ExecRequest)
		case env.ExecInput != nil:
			if b.onExecInput == nil {
				b.logger.Printf("ignoring unsupported helper envelope kind %q", env.Kind())
				continue
			}
			b.onExecInput(*env.ExecInput)
		default:
			b.logger.Printf("ignoring unsupported helper envelope kind %q", env.Kind())
		}
	}
}

func (b *RuntimeBridge) ProxyRoundTrip(ctx context.Context, req helperproto.ProxyRequest) (*helperproto.ProxyResponse, error) {
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

	if err := b.Send(helperproto.Envelope{
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

func (b *RuntimeBridge) Connect(ctx context.Context, host string, port int) (uint64, <-chan helperproto.Envelope, *helperproto.ConnectResponse, error) {
	id := b.nextID.Add(1)
	ch := make(chan helperproto.Envelope, 1)
	tunnelCh := b.RegisterTunnel(id)

	b.pendMu.Lock()
	b.pending[id] = ch
	b.pendMu.Unlock()

	defer func() {
		b.pendMu.Lock()
		delete(b.pending, id)
		b.pendMu.Unlock()
	}()

	if err := b.Send(helperproto.Envelope{
		ID: id,
		ConnectRequest: &helperproto.ConnectRequest{
			Host: host,
			Port: port,
		},
	}); err != nil {
		b.UnregisterTunnel(id)
		return id, nil, nil, err
	}

	select {
	case <-ctx.Done():
		b.UnregisterTunnel(id)
		return id, nil, nil, ctx.Err()
	case env := <-ch:
		if env.ConnectResponse == nil {
			b.UnregisterTunnel(id)
			return id, nil, nil, fmt.Errorf("bridge response %d did not contain a connect response", id)
		}
		return id, tunnelCh, env.ConnectResponse, nil
	}
}

func (b *RuntimeBridge) AuthorizeConnect(ctx context.Context, host string, port int) (*helperproto.ConnectResponse, error) {
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

	if err := b.Send(helperproto.Envelope{
		ID: id,
		ConnectRequest: &helperproto.ConnectRequest{
			Host: host,
			Port: port,
		},
	}); err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case env := <-ch:
		if env.ConnectResponse == nil {
			return nil, fmt.Errorf("bridge response %d did not contain a connect response", id)
		}
		return env.ConnectResponse, nil
	}
}

func (b *RuntimeBridge) RequestLeafCert(ctx context.Context, host string) (*helperproto.LeafCertResponse, error) {
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

	if err := b.Send(helperproto.Envelope{
		ID: id,
		LeafCertRequest: &helperproto.LeafCertRequest{
			Host: host,
		},
	}); err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case env := <-ch:
		if env.LeafCertResponse == nil {
			return nil, fmt.Errorf("bridge response %d did not contain a leaf cert response", id)
		}
		if env.LeafCertResponse.Error != "" {
			return nil, errors.New(env.LeafCertResponse.Error)
		}
		return env.LeafCertResponse, nil
	}
}

func (b *RuntimeBridge) MITMRoundTrip(ctx context.Context, req helperproto.MITMRequest) (*helperproto.MITMResponse, error) {
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

	if err := b.Send(helperproto.Envelope{
		ID:          id,
		MITMRequest: &req,
	}); err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case env := <-ch:
		if env.MITMResponse == nil {
			return nil, fmt.Errorf("bridge response %d did not contain a MITM response", id)
		}
		if env.MITMResponse.Error != "" && env.MITMResponse.StatusCode == 0 {
			return nil, errors.New(env.MITMResponse.Error)
		}
		return env.MITMResponse, nil
	}
}

func (b *RuntimeBridge) RegisterTunnel(id uint64) <-chan helperproto.Envelope {
	delivery := &tunnelDelivery{
		ch:     make(chan helperproto.Envelope, 32),
		closed: make(chan struct{}),
	}
	b.tunnelMu.Lock()
	b.tunnels[id] = delivery
	b.tunnelMu.Unlock()
	return delivery.ch
}

func (b *RuntimeBridge) UnregisterTunnel(id uint64) {
	b.tunnelMu.Lock()
	delivery := b.tunnels[id]
	delete(b.tunnels, id)
	b.tunnelMu.Unlock()
	if delivery != nil {
		close(delivery.closed)
	}
}

func (b *RuntimeBridge) TunnelCount() int {
	b.tunnelMu.Lock()
	defer b.tunnelMu.Unlock()
	return len(b.tunnels)
}

func (b *RuntimeBridge) DeliverTunnel(env helperproto.Envelope) {
	b.tunnelMu.Lock()
	delivery := b.tunnels[env.ID]
	b.tunnelMu.Unlock()
	if delivery == nil {
		b.logger.Printf("dropping tunnel message for unknown request %d", env.ID)
		return
	}

	select {
	case delivery.ch <- env:
	case <-delivery.closed:
		b.logger.Printf("dropping tunnel message for closed request %d", env.ID)
	}
}

func (b *RuntimeBridge) SendTunnelClose(id uint64, write bool, tunnelErr error) error {
	closeErr := ""
	if tunnelErr != nil && !errors.Is(tunnelErr, io.EOF) && !errors.Is(tunnelErr, net.ErrClosed) {
		closeErr = tunnelErr.Error()
	}
	return b.Send(helperproto.Envelope{
		ID: id,
		TunnelClose: &helperproto.TunnelClose{
			Write: write,
			Error: closeErr,
		},
	})
}

func (b *RuntimeBridge) RelayPayloadToTunnel(conn net.Conn, id uint64, bufferedPayload []byte) TunnelRelayResult {
	if len(bufferedPayload) > 0 {
		if sendErr := b.Send(helperproto.Envelope{
			ID: id,
			TunnelFrame: &helperproto.TunnelFrame{
				Data: append([]byte(nil), bufferedPayload...),
			},
		}); sendErr != nil {
			return TunnelRelayResult{SendClose: true, Err: sendErr, Terminal: true}
		}
	}

	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if sendErr := b.Send(helperproto.Envelope{
				ID: id,
				TunnelFrame: &helperproto.TunnelFrame{
					Data: append([]byte(nil), buf[:n]...),
				},
			}); sendErr != nil {
				return TunnelRelayResult{SendClose: true, Err: sendErr, Terminal: true}
			}
		}

		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			return TunnelRelayResult{SendClose: true, Write: true}
		}
		if errors.Is(err, net.ErrClosed) {
			return TunnelRelayResult{}
		}
		return TunnelRelayResult{SendClose: true, Err: err, Terminal: true}
	}
}

func (b *RuntimeBridge) RelayTunnelToPayload(ctx context.Context, conn net.Conn, tunnelCh <-chan helperproto.Envelope) TunnelRelayResult {
	for {
		select {
		case <-ctx.Done():
			return TunnelRelayResult{}
		case env, ok := <-tunnelCh:
			if !ok {
				return TunnelRelayResult{Terminal: true}
			}
			switch {
			case env.TunnelFrame != nil:
				if len(env.TunnelFrame.Data) == 0 {
					continue
				}
				if err := writeAll(conn, env.TunnelFrame.Data); err != nil {
					return TunnelRelayResult{SendClose: true, Err: err, Terminal: true}
				}
			case env.TunnelClose != nil:
				if env.TunnelClose.Write {
					if err := closePayloadWrite(conn); err != nil {
						return TunnelRelayResult{SendClose: true, Err: err, Terminal: true}
					}
					return TunnelRelayResult{}
				}
				return TunnelRelayResult{Terminal: true}
			default:
				b.logger.Printf("ignoring unexpected tunnel envelope kind %q", env.Kind())
			}
		}
	}
}

func (b *RuntimeBridge) Send(env helperproto.Envelope) error {
	b.sendMu.Lock()
	defer b.sendMu.Unlock()
	return b.enc.Encode(&env)
}

func (b *RuntimeBridge) handleHello(env helperproto.Envelope) error {
	if env.Hello.ProtocolVersion != helperproto.ProtocolVersion {
		return fmt.Errorf("unsupported protocol version %d", env.Hello.ProtocolVersion)
	}

	return b.Send(helperproto.Envelope{
		ID: env.ID,
		Ready: &helperproto.Ready{
			ProtocolVersion: helperproto.ProtocolVersion,
			ProxyAddr:       b.proxyAddr,
			DNSAddr:         b.dnsAddr,
			HTTPAddr:        b.httpAddr,
			HTTPSAddr:       b.httpsAddr,
		},
	})
}

func (b *RuntimeBridge) deliver(env helperproto.Envelope) {
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

func writeAll(dst net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := dst.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func closePayloadWrite(conn net.Conn) error {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return conn.Close()
}
