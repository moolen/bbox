package helperruntime

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/moolen/bbox/internal/helperproto"
	"github.com/moolen/bbox/internal/helperruntime/ingress"
	"github.com/moolen/bbox/internal/helperruntime/seccompnotify"
)

type rawTCPDestination struct {
	host string
	port int
}

type transparentNet struct {
	rawTCPMu      sync.Mutex
	rawTCPOrigins map[string]rawTCPDestination
	dns           *dnsCache
}

func newTransparentNet() *transparentNet {
	return &transparentNet{
		rawTCPOrigins: make(map[string]rawTCPDestination),
		dns:           newDNSCache(),
	}
}

const rawTCPOriginLookupTimeout = 1 * time.Second

func (b *bridge) proxyHandler() http.Handler {
	return ingress.ProxyHandler(b)
}

func (b *bridge) transparentHTTPHandler() http.Handler {
	return ingress.TransparentHTTPHandler(b)
}

func (b *bridge) handleTransparentTCPConn(conn net.Conn) {
	if conn == nil {
		return
	}

	host, port, _ := b.waitRawTCPOrigin(conn.RemoteAddr().String(), rawTCPOriginLookupTimeout)
	ingress.ServeTransparentTCPConn(conn, b, host, port)
}

func (b *bridge) handleMITMConnect(w http.ResponseWriter, req *http.Request) {
	ingress.HandleMITMConnect(b, w, req)
}

func (b *bridge) handleConnect(w http.ResponseWriter, req *http.Request) {
	ingress.HandleConnect(b, w, req)
}

func (b *bridge) transparentRuntime() seccompnotify.RuntimeTargets {
	return seccompnotify.RuntimeTargets{
		DNSRoundTrip:          b.dnsRoundTrip,
		RawTCPAddr:            b.rawTCPAddr,
		RawTCPAddrV6:          b.rawTCPAddrV6,
		RecordRawTCPOrigin:    b.recordRawTCPOrigin,
		PayloadSeccompBPFPath: b.payloadSeccompBPFPath,
	}
}

func (b *bridge) dnsRoundTrip(ctx context.Context, network, host string, port int, payload []byte) ([]byte, error) {
	if b == nil || b.runtimeBridge == nil {
		return nil, fmt.Errorf("runtime bridge is required")
	}
	reply, err := b.runtimeBridge.DNSRoundTrip(ctx, helperproto.DNSRequest{
		Network: network,
		Host:    host,
		Port:    port,
		Payload: append([]byte(nil), payload...),
	})
	if err != nil {
		return nil, err
	}
	b.rememberDNSResolution(payload, reply)
	return reply, nil
}

func (b *bridge) recordRawTCPOrigin(localAddr, host string, port int) {
	if b == nil || b.transparent == nil {
		return
	}
	b.transparent.recordRawTCPOrigin(localAddr, host, port)
}

func (b *bridge) rememberDNSResolution(query []byte, response []byte) {
	if b == nil || b.transparent == nil {
		return
	}
	b.transparent.rememberDNSResolution(query, response)
}

func (b *bridge) lookupResolvedHost(ip string, now time.Time) (string, bool) {
	if b == nil || b.transparent == nil {
		return "", false
	}
	return b.transparent.lookupResolvedHost(ip, now)
}

func (b *bridge) takeRawTCPOrigin(localAddr string) (string, int, bool) {
	if b == nil || b.transparent == nil {
		return "", 0, false
	}
	return b.transparent.takeRawTCPOrigin(localAddr)
}

func (b *bridge) waitRawTCPOrigin(localAddr string, timeout time.Duration) (string, int, bool) {
	if b == nil || b.transparent == nil {
		return "", 0, false
	}
	return b.transparent.waitRawTCPOrigin(localAddr, timeout)
}

func (n *transparentNet) recordRawTCPOrigin(localAddr, host string, port int) {
	if n == nil || localAddr == "" || host == "" || port < 1 || port > 65535 {
		return
	}
	if ip := net.ParseIP(host); ip != nil {
		if resolvedHost, ok := n.lookupResolvedHost(ip.String(), time.Now()); ok {
			host = resolvedHost
		}
	}
	localAddr = canonicalTCPOriginKey(localAddr)
	n.rawTCPMu.Lock()
	n.rawTCPOrigins[localAddr] = rawTCPDestination{host: host, port: port}
	n.rawTCPMu.Unlock()
}

func (n *transparentNet) rememberDNSResolution(query []byte, response []byte) {
	if n == nil || n.dns == nil {
		return
	}
	n.dns.remember(query, response)
}

func (n *transparentNet) lookupResolvedHost(ip string, now time.Time) (string, bool) {
	if n == nil || n.dns == nil {
		return "", false
	}
	return n.dns.lookupResolvedHost(ip, now)
}

func (n *transparentNet) takeRawTCPOrigin(localAddr string) (string, int, bool) {
	if n == nil || localAddr == "" {
		return "", 0, false
	}
	localAddr = canonicalTCPOriginKey(localAddr)

	n.rawTCPMu.Lock()
	dest, ok := n.rawTCPOrigins[localAddr]
	if ok {
		delete(n.rawTCPOrigins, localAddr)
	}
	n.rawTCPMu.Unlock()
	if !ok {
		return "", 0, false
	}
	return dest.host, dest.port, true
}

func (n *transparentNet) waitRawTCPOrigin(localAddr string, timeout time.Duration) (string, int, bool) {
	if timeout <= 0 {
		return n.takeRawTCPOrigin(localAddr)
	}

	deadline := time.Now().Add(timeout)
	for {
		host, port, ok := n.takeRawTCPOrigin(localAddr)
		if ok {
			return host, port, true
		}
		if time.Now().After(deadline) {
			return "", 0, false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func canonicalTCPOriginKey(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	if _, err := strconv.Atoi(port); err != nil {
		return addr
	}
	return net.JoinHostPort(host, port)
}
