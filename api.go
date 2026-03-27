package bbox

import (
	"fmt"
	"net"
	"strings"

	"github.com/moolen/bbox/internal/helperruntime"
)

func NewProxyManager(opts ProxyOptions) (*ProxyManager, error) {
	policy, err := compilePolicy(opts.NetworkPolicy)
	if err != nil {
		return nil, err
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
	return manager, nil
}
