package bbox

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/moolen/bbox/internal/helperruntime"
)

type stdoutJSONAccessLogger struct {
	mu  sync.Mutex
	enc *json.Encoder
}

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

// NewProxyManager validates the supplied options and returns a manager that can
// create multiple sandboxes sharing the same host-side proxy policy engine.
func NewProxyManager(opts ProxyOptions) (*ProxyManager, error) {
	policy, err := compilePolicy(opts.NetworkPolicy)
	if err != nil {
		return nil, err
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
	manager.mitm = opts.MITM
	if opts.AccessLogger == nil {
		manager.accessLogger = newStdoutJSONAccessLogger()
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
