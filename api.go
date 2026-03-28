package bbox

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/moolen/bbox/internal/helperruntime"
)

const (
	defaultMaxRequestBodyBytes  = 1 << 20
	defaultMaxResponseBodyBytes = 4 << 20
)

type stdoutJSONAccessLogger struct {
	mu  sync.Mutex
	enc *json.Encoder
}

var sharedStdoutAccessLogger = newStdoutJSONAccessLogger()

func newStdoutJSONAccessLogger() *stdoutJSONAccessLogger {
	return &stdoutJSONAccessLogger{enc: json.NewEncoder(os.Stdout)}
}

func (l *stdoutJSONAccessLogger) LogAccess(entry AccessLogEntry) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(entry)
}

func isNilAccessLogger(logger AccessLogger) bool {
	if logger == nil {
		return true
	}
	value := reflect.ValueOf(logger)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// NewProxyManager validates the supplied options and returns a manager that can
// create multiple sandboxes sharing the same host-side proxy policy engine.
func NewProxyManager(opts ProxyOptions) (*ProxyManager, error) {
	policy, err := compilePolicy(opts.NetworkPolicy)
	if err != nil {
		return nil, err
	}
	if opts.MaxRequestBodyBytes < 0 {
		return nil, fmt.Errorf("max request body bytes must be non-negative")
	}
	if opts.MaxResponseBodyBytes < 0 {
		return nil, fmt.Errorf("max response body bytes must be non-negative")
	}
	if opts.MITM.MaxRequestBodyBytes < 0 {
		return nil, fmt.Errorf("MITM max request body bytes must be non-negative")
	}

	listenAddr := strings.TrimSpace(opts.ListenAddr)
	if listenAddr == "" {
		listenAddr = helperruntime.DefaultProxyAddr
	}
	if _, err := net.ResolveTCPAddr("tcp", listenAddr); err != nil {
		return nil, fmt.Errorf("resolve proxy listen address %q: %w", listenAddr, err)
	}

	manager := newProxyManager(policy)
	manager.listenAddr = listenAddr
	manager.requestBodyLimitBytes = effectiveRequestBodyLimit(opts)
	manager.responseBodyLimitBytes = effectiveResponseBodyLimit(opts)
	manager.mitm = opts.MITM
	if isNilAccessLogger(opts.AccessLogger) {
		manager.accessLogger = sharedStdoutAccessLogger
	} else {
		manager.accessLogger = opts.AccessLogger
	}
	if opts.MITM.Enabled {
		manager.mitmCA, err = newMITMCA()
		if err != nil {
			return nil, err
		}
		manager.caCertPEM = manager.mitmCA.CertPEM()
	}
	return manager, nil
}

func effectiveRequestBodyLimit(opts ProxyOptions) int64 {
	if opts.MaxRequestBodyBytes > 0 {
		return opts.MaxRequestBodyBytes
	}
	if opts.MITM.MaxRequestBodyBytes > 0 {
		return opts.MITM.MaxRequestBodyBytes
	}
	return defaultMaxRequestBodyBytes
}

func effectiveResponseBodyLimit(opts ProxyOptions) int64 {
	if opts.MaxResponseBodyBytes > 0 {
		return opts.MaxResponseBodyBytes
	}
	return defaultMaxResponseBodyBytes
}
