package bbox

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const managerDNSDefaultTimeout = 5 * time.Second

type managerDNSService struct {
	dialContext func(context.Context, string, string) (net.Conn, error)
	servers     []string
	timeout     time.Duration
}

var newManagerDNSService = func() *managerDNSService {
	dialer := &net.Dialer{Timeout: managerDNSDefaultTimeout}
	return &managerDNSService{
		dialContext: dialer.DialContext,
		servers:     systemDNSServers(),
		timeout:     managerDNSDefaultTimeout,
	}
}

func (s *managerDNSService) HandleQuery(ctx context.Context, payload []byte) ([]byte, error) {
	return s.handleQuery(ctx, "udp", payload)
}

func (s *managerDNSService) HandleQueryWithNetwork(ctx context.Context, network string, payload []byte) ([]byte, error) {
	return s.handleQuery(ctx, network, payload)
}

func (s *managerDNSService) handleQuery(ctx context.Context, network string, payload []byte) ([]byte, error) {
	if s == nil {
		return nil, errors.New("dns service is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if len(payload) == 0 {
		return nil, errors.New("dns query payload is empty")
	}
	if err := validateDNSQuery(payload); err != nil {
		return nil, err
	}

	normalizedNetwork, err := normalizeDNSNetwork(network)
	if err != nil {
		return nil, err
	}

	servers := s.servers
	if len(servers) == 0 {
		servers = systemDNSServers()
	}

	var roundTripErr error
	for _, upstream := range servers {
		response, err := s.roundTrip(ctx, normalizedNetwork, upstream, payload)
		if err == nil {
			return response, nil
		}
		roundTripErr = errors.Join(roundTripErr, fmt.Errorf("%s %s: %w", normalizedNetwork, upstream, err))
	}
	if roundTripErr == nil {
		return nil, errors.New("no DNS servers configured")
	}
	return nil, roundTripErr
}

func (s *managerDNSService) roundTrip(ctx context.Context, network, upstream string, payload []byte) ([]byte, error) {
	dial := s.dialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: managerDNSDefaultTimeout}).DialContext
	}

	conn, err := dial(ctx, network, upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(deadlineFromContext(ctx, s.timeout)); err != nil {
		return nil, err
	}

	switch network {
	case "tcp":
		return roundTripDNSTCP(conn, payload)
	default:
		return roundTripDNSUDP(conn, payload)
	}
}

func roundTripDNSUDP(conn net.Conn, payload []byte) ([]byte, error) {
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}

	buf := make([]byte, 64*1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), buf[:n]...), nil
}

func roundTripDNSTCP(conn net.Conn, payload []byte) ([]byte, error) {
	if len(payload) > 0xffff {
		return nil, fmt.Errorf("dns payload length %d exceeds tcp frame maximum %d", len(payload), 0xffff)
	}

	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
	copy(frame[2:], payload)
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}

	var lengthBuf [2]byte
	if _, err := io.ReadFull(conn, lengthBuf[:]); err != nil {
		return nil, err
	}
	responseLen := int(binary.BigEndian.Uint16(lengthBuf[:]))
	response := make([]byte, responseLen)
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, err
	}
	return response, nil
}

func validateDNSQuery(payload []byte) error {
	var parser dnsmessage.Parser
	if _, err := parser.Start(payload); err != nil {
		return fmt.Errorf("parse dns query: %w", err)
	}
	if _, err := parser.AllQuestions(); err != nil {
		return fmt.Errorf("parse dns query questions: %w", err)
	}
	return nil
}

func dnsQuestionHosts(payload []byte) ([]string, error) {
	var parser dnsmessage.Parser
	if _, err := parser.Start(payload); err != nil {
		return nil, fmt.Errorf("parse dns query: %w", err)
	}
	questions, err := parser.AllQuestions()
	if err != nil {
		return nil, fmt.Errorf("parse dns query questions: %w", err)
	}

	seen := make(map[string]struct{}, len(questions))
	hosts := make([]string, 0, len(questions))
	for _, question := range questions {
		host := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(question.Name.String(), ".")))
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	return hosts, nil
}

func stripAAAARecords(payload []byte) ([]byte, error) {
	var msg dnsmessage.Message
	if err := msg.Unpack(payload); err != nil {
		return nil, fmt.Errorf("parse dns response: %w", err)
	}

	msg.Answers = filterAAAAResources(msg.Answers)
	msg.Authorities = filterAAAAResources(msg.Authorities)
	msg.Additionals = filterAAAAResources(msg.Additionals)

	filtered, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack dns response: %w", err)
	}
	return filtered, nil
}

func filterAAAAResources(resources []dnsmessage.Resource) []dnsmessage.Resource {
	if len(resources) == 0 {
		return nil
	}
	filtered := make([]dnsmessage.Resource, 0, len(resources))
	for _, resource := range resources {
		if resource.Header.Type == dnsmessage.TypeAAAA {
			continue
		}
		filtered = append(filtered, resource)
	}
	return filtered
}

func normalizeDNSNetwork(network string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "", "udp", "udp4", "udp6":
		return "udp", nil
	case "tcp", "tcp4", "tcp6":
		return "tcp", nil
	default:
		return "", fmt.Errorf("unsupported dns network %q", network)
	}
}

func deadlineFromContext(ctx context.Context, fallback time.Duration) time.Time {
	if fallback <= 0 {
		fallback = managerDNSDefaultTimeout
	}
	deadline := time.Now().Add(fallback)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		return ctxDeadline
	}
	return deadline
}

func systemDNSServers() []string {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return []string{"127.0.0.1:53"}
	}
	defer file.Close()

	var servers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		servers = append(servers, net.JoinHostPort(fields[1], "53"))
	}

	if len(servers) == 0 {
		return []string{"127.0.0.1:53"}
	}
	return servers
}
