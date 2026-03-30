package helperruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	dnsruntime "github.com/moolen/bbox/internal/helperruntime/dns"
)

func runTransparentMode(ctx context.Context, cfg Config) error {
	if cfg.DNSAddr == "" {
		cfg.DNSAddr = DefaultTransparentDNSAddr
	}

	dnsServer, err := dnsruntime.NewServer(cfg.DNSAddr)
	if err != nil {
		return fmt.Errorf("listen on DNS address %q: %w", cfg.DNSAddr, err)
	}
	defer dnsServer.Close()

	rawTCPListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen on transparent TCP ingress: %w", err)
	}
	defer rawTCPListener.Close()

	rawTCPListenerV6 := listenOptionalLoopbackTCP6()
	if rawTCPListenerV6 != nil {
		defer rawTCPListenerV6.Close()
	}

	bridge := newBridge(cfg.Bridge, cfg.Logger, "")
	bridge.trafficMode = TrafficModeTransparent
	bridge.mitmEnabled = cfg.MITMEnabled
	bridge.maxRequestBodyBytes = cfg.MaxRequestBodyBytes
	bridge.dnsAddr = dnsServer.Addr()
	bridge.rawTCPAddr = rawTCPListener.Addr().String()
	bridge.tcpAddr = bridge.rawTCPAddr
	if rawTCPListenerV6 != nil {
		bridge.rawTCPAddrV6 = rawTCPListenerV6.Addr().String()
	}

	errCh := make(chan error, 5)

	go func() {
		<-ctx.Done()

		_ = dnsServer.Close()
		_ = rawTCPListener.Close()
		if rawTCPListenerV6 != nil {
			_ = rawTCPListenerV6.Close()
		}
		_ = cfg.Bridge.Close()
	}()

	go func() {
		errCh <- dnsServer.Serve()
	}()
	go func() {
		errCh <- serveRawTCPListener(rawTCPListener, bridge)
	}()
	if rawTCPListenerV6 != nil {
		go func() {
			errCh <- serveRawTCPListener(rawTCPListenerV6, bridge)
		}()
	}
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

func listenOptionalLoopbackTCP6() net.Listener {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return nil
	}
	return listener
}

func serveRawTCPListener(listener net.Listener, bridge *bridge) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go bridge.handleTransparentTCPConn(conn)
	}
}
