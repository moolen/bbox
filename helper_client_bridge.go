package bbox

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/moolen/bbox/internal/helperproto"
)

type helperReady struct {
	proxyAddr string
	dnsAddr   string
	httpAddr  string
	httpsAddr string
	err       error
}

func (r helperReady) hasTransparentListeners() bool {
	return r.dnsAddr != "" && r.httpAddr != "" && r.httpsAddr != ""
}

func (c *helperClient) readLoop() error {
	defer c.cancel()

	for {
		var env helperproto.Envelope
		if err := c.dec.Decode(&env); err != nil {
			c.notifyReady(helperReady{err: err})
			c.failCurrentRun(err)
			c.shutdownTunnels()
			return err
		}

		switch {
		case env.Ready != nil:
			if env.Ready.ProtocolVersion != helperproto.ProtocolVersion {
				err := fmt.Errorf("unexpected helper protocol version %d", env.Ready.ProtocolVersion)
				c.notifyReady(helperReady{err: err})
				c.failCurrentRun(err)
				return err
			}
			c.notifyReady(helperReady{
				proxyAddr: env.Ready.ProxyAddr,
				dnsAddr:   env.Ready.DNSAddr,
				httpAddr:  env.Ready.HTTPAddr,
				httpsAddr: env.Ready.HTTPSAddr,
			})
		case env.ProxyRequest != nil:
			req := *env.ProxyRequest
			go c.handleProxyRequest(env.ID, req)
		case env.ConnectRequest != nil:
			req := *env.ConnectRequest
			go c.handleConnectRequest(env.ID, req)
		case env.LeafCertRequest != nil:
			req := *env.LeafCertRequest
			go c.handleLeafCertRequest(env.ID, req)
		case env.MITMRequest != nil:
			req := *env.MITMRequest
			go c.handleMITMRequest(env.ID, req)
		case env.TunnelFrame != nil:
			c.handleTunnelFrame(env.ID, *env.TunnelFrame)
		case env.TunnelClose != nil:
			c.handleTunnelClose(env.ID, *env.TunnelClose)
		case env.StreamFrame != nil:
			c.handleStream(*env.StreamFrame)
		case env.ExecResult != nil:
			c.handleExecResult(*env.ExecResult)
		}
	}
}

func (c *helperClient) notifyReady(ready helperReady) {
	c.readyOnce.Do(func() {
		c.readyCh <- ready
	})
}

func (c *helperClient) handleProxyRequest(id uint64, req helperproto.ProxyRequest) {
	response := c.manager.handleProxyRequest(c.ctx, c.sandboxID, req)
	if err := c.send(helperproto.Envelope{
		ID:            id,
		ProxyResponse: response,
	}); err != nil {
		c.failCurrentRun(err)
	}
}

func (c *helperClient) handleConnectRequest(id uint64, req helperproto.ConnectRequest) {
	response := c.manager.handleConnectRequest(c.ctx, c.sandboxID, req)
	if response == nil {
		response = &helperproto.ConnectResponse{
			StatusCode: http.StatusBadGateway,
			Error:      "connect request rejected: empty response",
		}
	}
	if response.StatusCode == 0 {
		response.StatusCode = http.StatusBadGateway
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_ = c.send(helperproto.Envelope{
			ID:              id,
			ConnectResponse: response,
		})
		return
	}

	conn, err := c.manager.dialTunnel(c.ctx, req.Host, req.Port)
	if err != nil {
		_ = c.send(helperproto.Envelope{
			ID: id,
			ConnectResponse: &helperproto.ConnectResponse{
				StatusCode: http.StatusBadGateway,
				Error:      err.Error(),
			},
		})
		return
	}

	tunnel := newHostTunnel(c, id, conn)
	c.registerPendingTunnel(id, tunnel)

	if err := c.send(helperproto.Envelope{
		ID:              id,
		ConnectResponse: response,
	}); err != nil {
		c.unregisterTunnel(id)
		tunnel.shutdown()
		return
	}

	if !c.activateTunnel(id) {
		tunnel.shutdown()
		return
	}
	tunnel.start()
}

func (c *helperClient) handleLeafCertRequest(id uint64, req helperproto.LeafCertRequest) {
	response := c.manager.handleLeafCertRequest(req.Host)
	if response == nil {
		response = &helperproto.LeafCertResponse{
			Error: "leaf cert request rejected: empty response",
		}
	}

	if err := c.send(helperproto.Envelope{
		ID:               id,
		LeafCertResponse: response,
	}); err != nil {
		c.failCurrentRun(err)
	}
}

func (c *helperClient) handleMITMRequest(id uint64, req helperproto.MITMRequest) {
	response := c.manager.handleMITMRequest(c.ctx, c.sandboxID, req)
	if response == nil {
		response = &helperproto.MITMResponse{
			StatusCode: http.StatusBadGateway,
			Error:      "MITM request rejected: empty response",
		}
	}
	if response.StatusCode == 0 {
		response.StatusCode = http.StatusBadGateway
	}
	if err := c.send(helperproto.Envelope{
		ID:           id,
		MITMResponse: response,
	}); err != nil {
		c.failCurrentRun(err)
	}
}

func normalizeLoopCloseError(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
