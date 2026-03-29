package helperruntime

import (
	"io"
	"log"
	"time"
)

const DefaultProxyAddr = "127.0.0.1:31111"
const DefaultTransparentDNSAddr = "127.0.0.1:53"
const DefaultTransparentHTTPAddr = "127.0.0.1:80"
const DefaultTransparentHTTPSAddr = "127.0.0.1:443"

const connectHandshakeTimeout = 5 * time.Second

type TrafficMode string

const (
	TrafficModeProxy       TrafficMode = "proxy"
	TrafficModeTransparent TrafficMode = "transparent"
)

type Config struct {
	Bridge              io.ReadWriteCloser
	TrafficMode         TrafficMode
	ProxyAddr           string
	DNSAddr             string
	HTTPAddr            string
	HTTPSAddr           string
	Logger              *log.Logger
	MITMEnabled         bool
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
