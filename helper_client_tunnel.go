package bbox

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/moolen/bbox/internal/helperproto"
)

type hostTunnel struct {
	client *helperClient
	id     uint64
	conn   net.Conn

	recvCh chan helperproto.Envelope
	closed chan struct{}

	closeOnce sync.Once

	sendWriteCloseOnce    sync.Once
	sendTerminalCloseOnce sync.Once
}

func newHostTunnel(client *helperClient, id uint64, conn net.Conn) *hostTunnel {
	return &hostTunnel{
		client: client,
		id:     id,
		conn:   conn,
		recvCh: make(chan helperproto.Envelope, 64),
		closed: make(chan struct{}),
	}
}

func (c *helperClient) registerPendingTunnel(id uint64, tunnel *hostTunnel) {
	c.tunnelMu.Lock()
	defer c.tunnelMu.Unlock()
	if c.pendingTunnels == nil {
		c.pendingTunnels = make(map[uint64]*hostTunnel)
	}
	c.pendingTunnels[id] = tunnel
}

func (c *helperClient) activateTunnel(id uint64) bool {
	c.tunnelMu.Lock()
	defer c.tunnelMu.Unlock()
	tunnel := c.pendingTunnels[id]
	if tunnel == nil {
		return false
	}
	delete(c.pendingTunnels, id)
	if c.tunnels == nil {
		c.tunnels = make(map[uint64]*hostTunnel)
	}
	c.tunnels[id] = tunnel
	return true
}

func (c *helperClient) unregisterTunnel(id uint64) *hostTunnel {
	c.tunnelMu.Lock()
	defer c.tunnelMu.Unlock()
	tunnel := c.tunnels[id]
	delete(c.tunnels, id)
	if tunnel == nil {
		tunnel = c.pendingTunnels[id]
	}
	delete(c.pendingTunnels, id)
	return tunnel
}

func (c *helperClient) tunnel(id uint64) *hostTunnel {
	c.tunnelMu.Lock()
	defer c.tunnelMu.Unlock()
	tunnel := c.tunnels[id]
	if tunnel != nil {
		return tunnel
	}
	return c.pendingTunnels[id]
}

func (c *helperClient) handleTunnelFrame(id uint64, frame helperproto.TunnelFrame) {
	tunnel := c.tunnel(id)
	if tunnel == nil {
		return
	}
	tunnel.deliver(helperproto.Envelope{
		ID:          id,
		TunnelFrame: &helperproto.TunnelFrame{Data: append([]byte(nil), frame.Data...)},
	})
}

func (c *helperClient) handleTunnelClose(id uint64, closeMsg helperproto.TunnelClose) {
	tunnel := c.tunnel(id)
	if tunnel == nil {
		return
	}
	tunnel.deliver(helperproto.Envelope{
		ID:          id,
		TunnelClose: &helperproto.TunnelClose{Write: closeMsg.Write, Error: closeMsg.Error},
	})
}

func (c *helperClient) shutdownTunnels() {
	c.tunnelMu.Lock()
	tunnels := make([]*hostTunnel, 0, len(c.tunnels)+len(c.pendingTunnels))
	for _, tunnel := range c.tunnels {
		tunnels = append(tunnels, tunnel)
	}
	for _, tunnel := range c.pendingTunnels {
		tunnels = append(tunnels, tunnel)
	}
	c.tunnels = make(map[uint64]*hostTunnel)
	c.pendingTunnels = make(map[uint64]*hostTunnel)
	c.tunnelMu.Unlock()

	for _, tunnel := range tunnels {
		tunnel.shutdown()
	}
}

func (t *hostTunnel) start() {
	go t.relayOutboundToTunnel()
	go t.relayTunnelToOutbound()
}

func (t *hostTunnel) deliver(env helperproto.Envelope) {
	select {
	case <-t.closed:
		return
	default:
	}

	select {
	case t.recvCh <- env:
	case <-t.closed:
	default:
		t.sendTerminalCloseAsync(errors.New("tunnel receive buffer overflow"))
		t.closeTerminal()
	}
}

func (t *hostTunnel) shutdown() {
	t.closeOnce.Do(func() {
		close(t.closed)
		_ = t.conn.Close()
	})
}

func (t *hostTunnel) SendWriteClose(err error) {
	t.sendWriteCloseOnce.Do(func() {
		_ = t.client.send(helperproto.Envelope{
			ID: t.id,
			TunnelClose: &helperproto.TunnelClose{
				Write: true,
				Error: normalizeTunnelError(err),
			},
		})
	})
}

func (t *hostTunnel) sendTerminalClose(err error) {
	t.sendTerminalCloseOnce.Do(func() {
		_ = t.client.send(helperproto.Envelope{
			ID: t.id,
			TunnelClose: &helperproto.TunnelClose{
				Write: false,
				Error: normalizeTunnelError(err),
			},
		})
	})
}

func (t *hostTunnel) sendTerminalCloseAsync(err error) {
	go t.sendTerminalClose(err)
}

func (t *hostTunnel) relayOutboundToTunnel() {
	buf := make([]byte, 32*1024)
	for {
		_ = t.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := t.conn.Read(buf)
		if n > 0 {
			if sendErr := t.client.send(helperproto.Envelope{
				ID: t.id,
				TunnelFrame: &helperproto.TunnelFrame{
					Data: append([]byte(nil), buf[:n]...),
				},
			}); sendErr != nil {
				t.sendTerminalClose(sendErr)
				t.closeTerminal()
				return
			}
		}

		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			t.SendWriteClose(nil)
			return
		}
		if errors.Is(err, net.ErrClosed) {
			return
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			continue
		}
		t.sendTerminalClose(err)
		t.closeTerminal()
		return
	}
}

func (t *hostTunnel) relayTunnelToOutbound() {
	defer func() {
		t.closeTerminal()
	}()

	for {
		select {
		case <-t.closed:
			return
		case env, ok := <-t.recvCh:
			if !ok {
				return
			}
			switch {
			case env.TunnelFrame != nil:
				if len(env.TunnelFrame.Data) == 0 {
					continue
				}
				_ = t.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if err := writeAll(t.conn, env.TunnelFrame.Data); err != nil {
					t.sendTerminalClose(err)
					return
				}
			case env.TunnelClose != nil:
				if env.TunnelClose.Write {
					if err := closeTunnelWrite(t.conn); err != nil {
						t.sendTerminalClose(err)
						return
					}
					continue
				}
				return
			default:
			}
		}
	}
}

func (t *hostTunnel) closeTerminal() {
	t.client.unregisterTunnel(t.id)
	t.shutdown()
}

func normalizeTunnelError(err error) string {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return ""
	}
	return err.Error()
}

func closeTunnelWrite(conn net.Conn) error {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return conn.Close()
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
