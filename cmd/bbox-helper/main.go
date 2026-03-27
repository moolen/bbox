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

	flag.IntVar(&bridgeFD, "bridge-fd", 3, "file descriptor carrying the helper control bridge")
	flag.StringVar(&proxyAddr, "proxy-addr", helperruntime.DefaultProxyAddr, "sandbox-local proxy listen address")
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
		Bridge:    bridge,
		ProxyAddr: proxyAddr,
		Logger:    logger,
	}); err != nil {
		logger.Fatal(err)
	}
}
