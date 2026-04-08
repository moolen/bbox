package bbox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/moolen/bbox/internal/helperproto"
)

type managerProxyConfig struct {
	transport            *http.Transport
	maxRequestBodyBytes  int64
	maxResponseBodyBytes int64
	policyMode           PolicyMode
	record               func(accessEvent)
}

type managerProxyService struct {
	transport            *http.Transport
	maxRequestBodyBytes  int64
	maxResponseBodyBytes int64
	policyMode           PolicyMode
	record               func(accessEvent)
}

func newManagerProxyService(cfg managerProxyConfig) *managerProxyService {
	transport := cfg.transport
	if transport == nil {
		transport = cloneDefaultTransport()
	}
	return &managerProxyService{
		transport:            transport,
		maxRequestBodyBytes:  cfg.maxRequestBodyBytes,
		maxResponseBodyBytes: cfg.maxResponseBodyBytes,
		policyMode:           normalizedPolicyModeOrDefault(cfg.policyMode),
		record:               cfg.record,
	}
}

func (s *managerProxyService) HandleProxyRequest(ctx context.Context, policy *compiledPolicy, sandboxID string, req helperproto.ProxyRequest) *helperproto.ProxyResponse {
	targetURL, err := url.Parse(req.URL)
	if err != nil {
		return &helperproto.ProxyResponse{Error: fmt.Sprintf("parse request URL %q: %v", req.URL, err)}
	}
	path := targetURL.Path
	if path == "" {
		path = "/"
	}
	port := 0
	if rawPort := targetURL.Port(); rawPort != "" {
		if parsed, err := strconv.Atoi(rawPort); err == nil {
			port = parsed
		}
	} else {
		switch strings.ToLower(targetURL.Scheme) {
		case "https":
			port = 443
		case "http":
			port = 80
		}
	}
	host, port := normalizeHostPort(targetURL.Host, port)
	protocol, protocolSource, protocolConfidence := classifyProxyAccessProtocol(targetURL.Scheme)
	policyEval := policy.evaluateRequest(PolicyRequest{
		Method: req.Method,
		Host:   targetURL.Host,
		Path:   path,
		Header: req.Header,
		Body:   req.Body,
	})
	event := eventWithPolicyMetadata(accessEvent{
		SandboxID:          sandboxID,
		Kind:               "http",
		Protocol:           protocol,
		ProtocolSource:     protocolSource,
		ProtocolConfidence: protocolConfidence,
		Host:               host,
		Port:               port,
		Method:             req.Method,
		Path:               path,
	}, s.policyMode, policyEval)
	if s.maxRequestBodyBytes > 0 && int64(len(req.Body)) > s.maxRequestBodyBytes {
		err := "request body exceeds inspection limit"
		event.Allowed = false
		event.StatusCode = http.StatusRequestEntityTooLarge
		event.Result = "denied"
		event.Error = err
		s.recordEvent(event)
		return &helperproto.ProxyResponse{
			StatusCode: http.StatusRequestEntityTooLarge,
			Header: http.Header{
				"Content-Type": []string{"text/plain; charset=utf-8"},
			},
			Body: []byte("proxy request denied: " + err + "\n"),
		}
	}
	if !policyEval.Allowed && s.policyMode != PolicyModeAudit {
		err := policyEval.firstReasonAsError()
		event.Allowed = false
		event.StatusCode = http.StatusForbidden
		event.Result = "denied"
		event.Error = err.Error()
		s.recordEvent(event)
		return &helperproto.ProxyResponse{
			StatusCode: http.StatusForbidden,
			Header: http.Header{
				"Content-Type": []string{"text/plain; charset=utf-8"},
			},
			Body: []byte("proxy request denied: " + err.Error() + "\n"),
		}
	}

	outReq, err := http.NewRequestWithContext(ctx, req.Method, targetURL.String(), bytes.NewReader(req.Body))
	if err != nil {
		event.Allowed = true
		event.Result = "upstream_error"
		event.Error = err.Error()
		s.recordEvent(event)
		return &helperproto.ProxyResponse{Error: fmt.Sprintf("build outbound request: %v", err)}
	}
	outReq.Header = req.Header.Clone()
	outReq.Host = targetURL.Host

	resp, err := s.transport.RoundTrip(outReq)
	if err != nil {
		event.Allowed = true
		event.Result = "upstream_error"
		event.Error = err.Error()
		s.recordEvent(event)
		return &helperproto.ProxyResponse{Error: err.Error()}
	}
	body, tooLarge, err := readBoundedResponse(resp.Body, s.maxResponseBodyBytes)
	if err != nil {
		event.Allowed = true
		event.StatusCode = resp.StatusCode
		event.Result = "upstream_error"
		event.Error = err.Error()
		s.recordEvent(event)
		return &helperproto.ProxyResponse{Error: fmt.Sprintf("read outbound response body: %v", err)}
	}
	if tooLarge {
		err := "upstream response body exceeds configured limit"
		event.Allowed = true
		event.StatusCode = resp.StatusCode
		event.Result = "upstream_error"
		event.Error = err
		s.recordEvent(event)
		return &helperproto.ProxyResponse{Error: err}
	}

	event.Allowed = true
	event.StatusCode = resp.StatusCode
	event.Result = "allowed"
	event.Error = ""
	s.recordEvent(event)
	return &helperproto.ProxyResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       body,
	}
}

func (s *managerProxyService) HandleMITMRequest(ctx context.Context, policy *compiledPolicy, sandboxID string, req helperproto.MITMRequest) *helperproto.MITMResponse {
	scheme := req.Scheme
	if scheme == "" {
		scheme = "https"
	}
	authority := req.Authority
	if authority == "" {
		authority = req.Host
	}
	policyHost := req.Host
	if policyHost == "" {
		policyHost = authority
	}
	path := req.Path
	if path == "" {
		path = "/"
	}
	host, port := mitmHostPort(req.Host, authority, scheme)
	protocol, protocolSource, protocolConfidence := classifyMITMAccessProtocol(req)
	policyEval := policy.evaluateRequest(PolicyRequest{
		Method:       req.Method,
		Host:         policyHost,
		Path:         req.Path,
		Header:       req.Header,
		Body:         req.Body,
		BodyTooLarge: req.BodyTooLarge,
	})
	event := eventWithPolicyMetadata(accessEvent{
		SandboxID:          sandboxID,
		Kind:               "mitm",
		Protocol:           protocol,
		ProtocolSource:     protocolSource,
		ProtocolConfidence: protocolConfidence,
		Host:               host,
		Port:               port,
		Method:             req.Method,
		Path:               path,
	}, s.policyMode, policyEval)
	if req.BodyTooLarge {
		event.Allowed = false
		event.StatusCode = http.StatusRequestEntityTooLarge
		event.Result = "denied"
		event.Error = "request body exceeds inspection limit"
		s.recordEvent(event)
		return &helperproto.MITMResponse{
			StatusCode: http.StatusRequestEntityTooLarge,
			Header: http.Header{
				"Content-Type": []string{"text/plain; charset=utf-8"},
			},
			Body: []byte("proxy request denied: request body exceeds inspection limit\n"),
		}
	}

	if err := validateMITMHostAuthority(policyHost, authority); err != nil {
		event.Allowed = false
		event.StatusCode = http.StatusForbidden
		event.Result = "denied"
		event.Error = err.Error()
		s.recordEvent(event)
		return &helperproto.MITMResponse{
			StatusCode: http.StatusForbidden,
			Header: http.Header{
				"Content-Type": []string{"text/plain; charset=utf-8"},
			},
			Body: []byte("proxy request denied: " + err.Error() + "\n"),
		}
	}

	if s.maxRequestBodyBytes > 0 && int64(len(req.Body)) > s.maxRequestBodyBytes {
		event.Allowed = false
		event.StatusCode = http.StatusRequestEntityTooLarge
		event.Result = "denied"
		event.Error = "request body exceeds inspection limit"
		s.recordEvent(event)
		return &helperproto.MITMResponse{
			StatusCode: http.StatusRequestEntityTooLarge,
			Header: http.Header{
				"Content-Type": []string{"text/plain; charset=utf-8"},
			},
			Body: []byte("proxy request denied: request body exceeds inspection limit\n"),
		}
	}

	if !policyEval.Allowed && s.policyMode != PolicyModeAudit {
		err := policyEval.firstReasonAsError()
		event.Allowed = false
		event.StatusCode = http.StatusForbidden
		event.Result = "denied"
		event.Error = err.Error()
		s.recordEvent(event)
		return &helperproto.MITMResponse{
			StatusCode: http.StatusForbidden,
			Header: http.Header{
				"Content-Type": []string{"text/plain; charset=utf-8"},
			},
			Body: []byte("proxy request denied: " + err.Error() + "\n"),
		}
	}
	if authority == "" {
		event.Allowed = false
		event.StatusCode = http.StatusBadRequest
		event.Result = "denied"
		event.Error = "MITM request authority is required"
		s.recordEvent(event)
		return &helperproto.MITMResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "MITM request authority is required",
		}
	}

	targetURL := &url.URL{
		Scheme:   scheme,
		Host:     authority,
		Path:     path,
		RawQuery: req.RawQuery,
	}
	outReq, err := http.NewRequestWithContext(ctx, req.Method, targetURL.String(), bytes.NewReader(req.Body))
	if err != nil {
		event.Allowed = true
		event.Result = "upstream_error"
		event.Error = err.Error()
		s.recordEvent(event)
		return &helperproto.MITMResponse{
			StatusCode: http.StatusBadGateway,
			Error:      fmt.Sprintf("build outbound MITM request: %v", err),
		}
	}
	outReq.Header = req.Header.Clone()
	if outReq.Header == nil {
		outReq.Header = make(http.Header)
	}
	if req.Host != "" {
		outReq.Host = req.Host
	}

	resp, err := s.transport.RoundTrip(outReq)
	if err != nil {
		event.Allowed = true
		event.Result = "upstream_error"
		event.Error = err.Error()
		s.recordEvent(event)
		return &helperproto.MITMResponse{
			StatusCode: http.StatusBadGateway,
			Error:      err.Error(),
		}
	}
	body, tooLarge, err := readBoundedResponse(resp.Body, s.maxResponseBodyBytes)
	if err != nil {
		event.Allowed = true
		event.StatusCode = resp.StatusCode
		event.Result = "upstream_error"
		event.Error = err.Error()
		s.recordEvent(event)
		return &helperproto.MITMResponse{
			StatusCode: http.StatusBadGateway,
			Error:      fmt.Sprintf("read outbound MITM response body: %v", err),
		}
	}
	if tooLarge {
		err := "upstream response body exceeds configured limit"
		event.Allowed = true
		event.StatusCode = resp.StatusCode
		event.Result = "upstream_error"
		event.Error = err
		s.recordEvent(event)
		return &helperproto.MITMResponse{
			StatusCode: http.StatusBadGateway,
			Error:      err,
		}
	}

	event.Allowed = true
	event.StatusCode = resp.StatusCode
	event.Result = "allowed"
	event.Error = ""
	s.recordEvent(event)
	return &helperproto.MITMResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       body,
	}
}

func (s *managerProxyService) CloseIdleConnections() {
	if s == nil || s.transport == nil {
		return
	}
	s.transport.CloseIdleConnections()
}

func (s *managerProxyService) recordEvent(event accessEvent) {
	if s == nil || s.record == nil {
		return
	}
	s.record(event)
}

func readBoundedResponse(body io.ReadCloser, maxBytes int64) ([]byte, bool, error) {
	if body == nil {
		return nil, false, nil
	}
	defer body.Close()

	if maxBytes <= 0 {
		data, err := io.ReadAll(body)
		return data, false, err
	}

	limited, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(limited)) > maxBytes {
		return limited[:maxBytes], true, nil
	}
	return limited, false, nil
}

func validateMITMHostAuthority(requestHost, authority string) error {
	if strings.TrimSpace(authority) == "" || strings.TrimSpace(requestHost) == "" {
		return nil
	}

	normalizedRequestHost, err := normalizePolicyHostname(requestHost)
	if err != nil {
		return err
	}
	normalizedAuthorityHost, err := normalizePolicyHostname(authority)
	if err != nil {
		return err
	}
	if normalizedRequestHost != normalizedAuthorityHost {
		return fmt.Errorf("request host %q does not match upstream authority %q", normalizedRequestHost, normalizedAuthorityHost)
	}
	return nil
}

func authorityPort(authority string) string {
	if authority == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(authority)
	if err != nil {
		return ""
	}
	return port
}

func mitmHostPort(requestHost, authority, scheme string) (string, int) {
	requestHost = strings.TrimSpace(requestHost)
	base := requestHost
	if base == "" {
		base = authority
	}
	if base == "" {
		return normalizeHostPort(base, 0)
	}
	if requestHost != "" {
		if rawPort := authorityPort(base); rawPort != "" {
			if parsed, err := strconv.Atoi(rawPort); err == nil {
				return normalizeHostPort(base, parsed)
			}
			return normalizeHostPort(base, 0)
		}
		if rawPort := authorityPort(authority); rawPort != "" {
			if parsed, err := strconv.Atoi(rawPort); err == nil {
				return normalizeHostPort(base, parsed)
			}
		}
		port := defaultPortForScheme(scheme)
		return normalizeHostPort(base, port)
	}

	port := 0
	if rawPort := authorityPort(base); rawPort != "" {
		if parsed, err := strconv.Atoi(rawPort); err == nil {
			port = parsed
		}
	} else {
		port = defaultPortForScheme(scheme)
	}
	return normalizeHostPort(base, port)
}

func defaultPortForScheme(scheme string) int {
	switch strings.ToLower(scheme) {
	case "https":
		return 443
	case "http":
		return 80
	default:
		return 0
	}
}

func classifyProxyAccessProtocol(scheme string) (string, string, string) {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "https":
		return "https", "http_headers", "definite"
	case "http", "":
		return "http", "http_headers", "definite"
	default:
		return strings.ToLower(strings.TrimSpace(scheme)), "http_headers", "probable"
	}
}

func classifyMITMAccessProtocol(req helperproto.MITMRequest) (string, string, string) {
	if isGRPCMITMRequest(req) {
		return "grpc", "http_headers", "definite"
	}
	return "https", "http_connect", "definite"
}

func isGRPCMITMRequest(req helperproto.MITMRequest) bool {
	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(req.Proto)), "HTTP/2") {
		return false
	}
	contentType := strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Type")))
	return strings.HasPrefix(contentType, "application/grpc")
}
