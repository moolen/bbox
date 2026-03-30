package helperentrypoint

import (
	"context"
	"io"
	"testing"

	"github.com/moolen/bbox/internal/helperruntime"
)

func TestRunParsesHelperFlagsAndCallsRuntime(t *testing.T) {
	openBridgeFromFD = func(int) (io.ReadWriteCloser, error) { return nopBridge{}, nil }
	t.Cleanup(func() { openBridgeFromFD = helperruntime.OpenBridgeFromFD })

	called := false
	runHelperRuntime = func(ctx context.Context, cfg helperruntime.Config) error {
		called = true
		if cfg.TrafficMode != helperruntime.TrafficModeTransparent {
			t.Fatalf("traffic mode = %q", cfg.TrafficMode)
		}
		if cfg.ProxyAddr != "127.0.0.1:31111" {
			t.Fatalf("proxy addr = %q", cfg.ProxyAddr)
		}
		return nil
	}
	t.Cleanup(func() { runHelperRuntime = helperruntime.Run })

	if err := Run([]string{
		"--bridge-fd", "7",
		"--proxy-addr", "127.0.0.1:31111",
		"--traffic-mode", "transparent",
		"--mitm-enabled=true",
		"child-proxy",
	}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected helper runtime to be invoked")
	}
}

func TestValidateArgsRejectsRemovedDNSAddrFlag(t *testing.T) {
	if err := ValidateArgs([]string{"--dns-addr", "127.0.0.1:53", "child-proxy"}); err == nil {
		t.Fatal("expected removed --dns-addr flag to be rejected")
	}
}

type nopBridge struct{}

func (nopBridge) Read([]byte) (int, error)    { return 0, io.EOF }
func (nopBridge) Write(p []byte) (int, error) { return len(p), nil }
func (nopBridge) Close() error                { return nil }
