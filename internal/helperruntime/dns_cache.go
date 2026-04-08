package helperruntime

import (
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type dnsResolutionEntry struct {
	host    string
	expires time.Time
}

type dnsCache struct {
	mu       sync.Mutex
	hostByIP map[string]dnsResolutionEntry
}

func newDNSCache() *dnsCache {
	return &dnsCache{
		hostByIP: make(map[string]dnsResolutionEntry),
	}
}

func (c *dnsCache) remember(query []byte, response []byte) {
	if c == nil {
		return
	}
	host, ips, ttl, ok := parseDNSResolution(query, response)
	if !ok || len(ips) == 0 {
		return
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	expires := time.Now().Add(ttl)

	c.mu.Lock()
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		c.hostByIP[ip] = dnsResolutionEntry{
			host:    host,
			expires: expires,
		}
	}
	c.mu.Unlock()
}

func (c *dnsCache) lookupResolvedHost(ip string, now time.Time) (string, bool) {
	if c == nil || ip == "" {
		return "", false
	}
	if now.IsZero() {
		now = time.Now()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.hostByIP[ip]
	if !ok {
		return "", false
	}
	if !entry.expires.IsZero() && now.After(entry.expires) {
		delete(c.hostByIP, ip)
		return "", false
	}
	if strings.TrimSpace(entry.host) == "" {
		return "", false
	}
	return entry.host, true
}

func parseDNSResolution(query []byte, response []byte) (string, []string, time.Duration, bool) {
	var queryMessage dnsmessage.Message
	if err := queryMessage.Unpack(query); err != nil {
		return "", nil, 0, false
	}
	if len(queryMessage.Questions) == 0 {
		return "", nil, 0, false
	}
	host := normalizeDNSName(queryMessage.Questions[0].Name.String())
	if host == "" {
		return "", nil, 0, false
	}

	var responseMessage dnsmessage.Message
	if err := responseMessage.Unpack(response); err != nil {
		return "", nil, 0, false
	}

	ips := make([]string, 0, len(responseMessage.Answers))
	var ttlSeconds uint32
	for _, answer := range responseMessage.Answers {
		switch body := answer.Body.(type) {
		case *dnsmessage.AResource:
			ips = append(ips, net.IP(body.A[:]).String())
		case *dnsmessage.AAAAResource:
			ips = append(ips, net.IP(body.AAAA[:]).String())
		default:
			continue
		}
		if answer.Header.TTL > 0 && (ttlSeconds == 0 || answer.Header.TTL < ttlSeconds) {
			ttlSeconds = answer.Header.TTL
		}
	}
	if len(ips) == 0 {
		return "", nil, 0, false
	}
	return host, ips, time.Duration(ttlSeconds) * time.Second, true
}

func normalizeDNSName(name string) string {
	name = strings.TrimSpace(strings.TrimSuffix(name, "."))
	return strings.ToLower(name)
}
