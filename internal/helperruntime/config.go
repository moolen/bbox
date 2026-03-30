package helperruntime

import (
	"io"
	"log"
	"time"
)

const DefaultProxyAddr = "127.0.0.1:31111"
const DefaultTransparentDNSAddr = "127.0.0.1:53"

const connectHandshakeTimeout = 5 * time.Second

type TrafficMode string

const (
	TrafficModeProxy       TrafficMode = "proxy"
	TrafficModeTransparent TrafficMode = "transparent"
)

// Config controls how the helper runtime exposes ingress listeners and how it
// talks back to the manager over the control bridge.
type Config struct {
	Bridge      io.ReadWriteCloser
	TrafficMode TrafficMode
	ProxyAddr   string
	// DNSAddr is the only transparent-mode listener that still binds directly on
	// its configured address because DNS interception stays protocol-specific.
	DNSAddr     string
	Logger      *log.Logger
	MITMEnabled bool

	MaxRequestBodyBytes int64
}

func withDefaults(cfg Config) Config {
	if cfg.Logger == nil {
		cfg.Logger = log.New(io.Discard, "", 0)
	}
	if cfg.TrafficMode == "" {
		cfg.TrafficMode = TrafficModeProxy
	}

	return cfg
}
