package helperruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	dnsruntime "github.com/moolen/bbox/internal/helperruntime/dns"
)

func runTransparentMode(ctx context.Context, cfg Config) error {
	if cfg.DNSAddr == "" {
		cfg.DNSAddr = DefaultTransparentDNSAddr
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = DefaultTransparentHTTPAddr
	}
	if cfg.HTTPSAddr == "" {
		cfg.HTTPSAddr = DefaultTransparentHTTPSAddr
	}

	dnsServer, err := dnsruntime.NewServer(cfg.DNSAddr)
	if err != nil {
		return fmt.Errorf("listen on DNS address %q: %w", cfg.DNSAddr, err)
	}
	defer dnsServer.Close()

	httpListener, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return fmt.Errorf("listen on HTTP address %q: %w", cfg.HTTPAddr, err)
	}
	defer httpListener.Close()

	httpsListener, err := net.Listen("tcp", cfg.HTTPSAddr)
	if err != nil {
		return fmt.Errorf("listen on HTTPS address %q: %w", cfg.HTTPSAddr, err)
	}
	defer httpsListener.Close()

	bridge := newBridge(cfg.Bridge, cfg.Logger, "")
	bridge.trafficMode = TrafficModeTransparent
	bridge.mitmEnabled = cfg.MITMEnabled
	bridge.maxRequestBodyBytes = cfg.MaxRequestBodyBytes
	bridge.dnsAddr = dnsServer.Addr()
	bridge.httpAddr = httpListener.Addr().String()
	bridge.httpsAddr = httpsListener.Addr().String()

	httpServer := &http.Server{
		Handler: bridge.transparentHTTPHandler(),
	}

	errCh := make(chan error, 4)

	go func() {
		<-ctx.Done()

		_ = dnsServer.Close()
		_ = httpServer.Shutdown(context.Background())
		_ = httpListener.Close()
		_ = httpsListener.Close()
		_ = cfg.Bridge.Close()
	}()

	go func() {
		errCh <- dnsServer.Serve()
	}()
	go func() {
		if err := httpServer.Serve(httpListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("serve transparent HTTP listener: %w", err)
		}
	}()
	go func() {
		errCh <- serveTransparentListener(httpsListener, bridge)
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

func serveTransparentListener(listener net.Listener, bridge *bridge) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go bridge.handleTransparentHTTPSConn(conn)
	}
}
