package bbox

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/moolen/bbox/internal/helperruntime"
	"golang.org/x/term"
)

const (
	defaultMaxRequestBodyBytes  = 1 << 20
	defaultMaxResponseBodyBytes = 4 << 20
)

type defaultJSONAccessLogger struct {
	mu          sync.Mutex
	enc         *json.Encoder
	deferOutput bool
	entries     []AccessLogEntry
}

func newDefaultJSONAccessLogger(w io.Writer) *defaultJSONAccessLogger {
	return newDefaultJSONAccessLoggerWithMode(w, writerIsTerminal(w))
}

func newDefaultJSONAccessLoggerWithMode(w io.Writer, deferOutput bool) *defaultJSONAccessLogger {
	logger := &defaultJSONAccessLogger{}
	if w != nil {
		logger.enc = json.NewEncoder(w)
	}
	logger.deferOutput = deferOutput
	return logger
}

func (l *defaultJSONAccessLogger) LogAccess(entry AccessLogEntry) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.deferOutput {
		l.entries = append(l.entries, entry)
		return
	}
	if l.enc == nil {
		return
	}
	_ = l.enc.Encode(entry)
}

func (l *defaultJSONAccessLogger) Flush() {
	if l == nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.deferOutput || l.enc == nil || len(l.entries) == 0 {
		return
	}
	for _, entry := range l.entries {
		_ = l.enc.Encode(entry)
	}
	l.entries = nil
}

func writerIsTerminal(w io.Writer) bool {
	if w == nil {
		return false
	}
	file, ok := w.(interface{ Fd() uintptr })
	if !ok {
		return false
	}
	return term.IsTerminal(int(file.Fd()))
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
	policyMode, err := normalizePolicyMode(opts.PolicyMode)
	if err != nil {
		return nil, err
	}
	if opts.MaxRequestBodyBytes < 0 {
		return nil, fmt.Errorf("max request body bytes must be non-negative")
	}
	if opts.MaxResponseBodyBytes < 0 {
		return nil, fmt.Errorf("max response body bytes must be non-negative")
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
	manager.policyMode = policyMode
	manager.reporting = opts.Reporting
	if isNilAccessLogger(opts.AccessLogger) {
		manager.accessLogger = newDefaultJSONAccessLogger(os.Stderr)
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
	return defaultMaxRequestBodyBytes
}

func effectiveResponseBodyLimit(opts ProxyOptions) int64 {
	if opts.MaxResponseBodyBytes > 0 {
		return opts.MaxResponseBodyBytes
	}
	return defaultMaxResponseBodyBytes
}

func normalizePolicyMode(mode PolicyMode) (PolicyMode, error) {
	switch mode {
	case "":
		return PolicyModeEnforce, nil
	case PolicyModeEnforce, PolicyModeAudit:
		return mode, nil
	default:
		return "", fmt.Errorf("invalid policy mode %q", mode)
	}
}
