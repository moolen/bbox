package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/moolen/bbox/internal/helperruntime"
)

type helperFlags struct {
	bridgeFD            int
	proxyAddr           string
	dnsAddr             string
	mitmEnabled         bool
	maxRequestBodyBytes int64
	trafficMode         string
}

func parseFlags(args []string) (helperFlags, error) {
	var parsed helperFlags
	fs := flag.NewFlagSet("bbox-helper", flag.ContinueOnError)
	fs.IntVar(&parsed.bridgeFD, "bridge-fd", 3, "file descriptor carrying the helper control bridge")
	fs.StringVar(&parsed.proxyAddr, "proxy-addr", helperruntime.DefaultProxyAddr, "sandbox-local proxy listen address")
	fs.StringVar(&parsed.dnsAddr, "dns-addr", "", "sandbox-local transparent DNS listen address")
	fs.BoolVar(&parsed.mitmEnabled, "mitm-enabled", false, "enable TLS MITM interception for CONNECT requests")
	fs.Int64Var(&parsed.maxRequestBodyBytes, "max-request-body-bytes", 0, "maximum intercepted request body bytes to buffer for policy evaluation")
	fs.StringVar(&parsed.trafficMode, "traffic-mode", string(helperruntime.TrafficModeProxy), "traffic mode (proxy or transparent)")
	if err := fs.Parse(args); err != nil {
		return parsed, err
	}
	if fs.NArg() > 0 && fs.Arg(0) != "child-proxy" {
		return parsed, fmt.Errorf("unexpected subcommand %q", fs.Arg(0))
	}
	return parsed, nil
}

func main() {
	parsed, err := parseFlags(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}

	bridge, err := helperruntime.OpenBridgeFromFD(parsed.bridgeFD)
	if err != nil {
		log.Fatal(err)
	}
	defer bridge.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := log.New(os.Stderr, "bbox-helper: ", log.LstdFlags)
	if err := helperruntime.Run(ctx, helperruntime.Config{
		Bridge:              bridge,
		TrafficMode:         helperruntime.TrafficMode(parsed.trafficMode),
		ProxyAddr:           parsed.proxyAddr,
		DNSAddr:             parsed.dnsAddr,
		Logger:              logger,
		MITMEnabled:         parsed.mitmEnabled,
		MaxRequestBodyBytes: parsed.maxRequestBodyBytes,
	}); err != nil {
		logger.Fatal(err)
	}
}
