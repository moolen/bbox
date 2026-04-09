package helperruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

func runProxyMode(ctx context.Context, cfg Config) error {
	if cfg.ProxyAddr == "" {
		cfg.ProxyAddr = DefaultProxyAddr
	}

	listener, err := net.Listen("tcp", cfg.ProxyAddr)
	if err != nil {
		return fmt.Errorf("listen on proxy address %q: %w", cfg.ProxyAddr, err)
	}
	defer listener.Close()

	bridge := newBridge(cfg.Bridge, cfg.Logger, listener.Addr().String())
	bridge.trafficMode = TrafficModeProxy
	bridge.mitmEnabled = cfg.MITMEnabled
	bridge.maxRequestBodyBytes = cfg.MaxRequestBodyBytes
	bridge.payloadSeccompBPFPath = cfg.PayloadSeccompBPFPath

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
