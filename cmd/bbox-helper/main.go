package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/moolen/bbox/internal/helperruntime"
)

func main() {
	var bridgeFD int
	var proxyAddr string
	var mitmEnabled bool
	var maxRequestBodyBytes int64

	flag.IntVar(&bridgeFD, "bridge-fd", 3, "file descriptor carrying the helper control bridge")
	flag.StringVar(&proxyAddr, "proxy-addr", helperruntime.DefaultProxyAddr, "sandbox-local proxy listen address")
	flag.BoolVar(&mitmEnabled, "mitm-enabled", false, "enable TLS MITM interception for CONNECT requests")
	flag.Int64Var(&maxRequestBodyBytes, "max-request-body-bytes", 0, "maximum intercepted request body bytes to buffer for policy evaluation")
	flag.Parse()

	if flag.NArg() > 0 && flag.Arg(0) != "child-proxy" {
		log.Fatalf("unexpected subcommand %q", flag.Arg(0))
	}

	bridge, err := helperruntime.OpenBridgeFromFD(bridgeFD)
	if err != nil {
		log.Fatal(err)
	}
	defer bridge.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := log.New(os.Stderr, "bbox-helper: ", log.LstdFlags)
	if err := helperruntime.Run(ctx, helperruntime.Config{
		Bridge:              bridge,
		ProxyAddr:           proxyAddr,
		Logger:              logger,
		MITMEnabled:         mitmEnabled,
		MaxRequestBodyBytes: maxRequestBodyBytes,
	}); err != nil {
		logger.Fatal(err)
	}
}
