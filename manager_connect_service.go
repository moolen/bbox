package bbox

import (
	"context"
	"net"
	"net/http"
	"strconv"

	"github.com/moolen/bbox/internal/helperproto"
)

type managerConnectService struct {
	record func(accessEvent)
}

func newManagerConnectService(record func(accessEvent)) *managerConnectService {
	return &managerConnectService{record: record}
}

func (s *managerConnectService) HandleConnectRequest(_ context.Context, policy *compiledPolicy, sandboxID string, req helperproto.ConnectRequest) *helperproto.ConnectResponse {
	host, port := normalizeHostPort(req.Host, req.Port)
	var err error
	if req.Transparent {
		err = policy.CheckTransparentConnect(req.Host)
	} else {
		hostport := net.JoinHostPort(req.Host, strconv.Itoa(req.Port))
		err = policy.Check(http.MethodConnect, hostport, true)
	}
	if err != nil {
		s.recordEvent(accessEvent{
			SandboxID:  sandboxID,
			Kind:       connectAccessKind(req.Transparent),
			Host:       host,
			Port:       port,
			Method:     http.MethodConnect,
			Allowed:    false,
			StatusCode: http.StatusForbidden,
			Result:     "denied",
			Error:      err.Error(),
		})
		return &helperproto.ConnectResponse{
			StatusCode: http.StatusForbidden,
			Message:    "connect request denied",
			Error:      err.Error(),
		}
	}

	s.recordEvent(accessEvent{
		SandboxID:  sandboxID,
		Kind:       connectAccessKind(req.Transparent),
		Host:       host,
		Port:       port,
		Method:     http.MethodConnect,
		Allowed:    true,
		StatusCode: http.StatusOK,
		Result:     "allowed",
	})
	return &helperproto.ConnectResponse{StatusCode: http.StatusOK}
}

func connectAccessKind(transparent bool) string {
	if transparent {
		return "transparent_connect"
	}
	return "connect"
}

func (s *managerConnectService) recordEvent(event accessEvent) {
	if s == nil || s.record == nil {
		return
	}
	s.record(event)
}
