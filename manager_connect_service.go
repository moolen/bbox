package bbox

import (
	"context"
	"net/http"

	"github.com/moolen/bbox/internal/helperproto"
)

type managerConnectService struct {
	record     func(accessEvent)
	policyMode PolicyMode
}

func newManagerConnectService(record func(accessEvent), policyMode PolicyMode) *managerConnectService {
	return &managerConnectService{
		record:     record,
		policyMode: normalizedPolicyModeOrDefault(policyMode),
	}
}

func (s *managerConnectService) HandleConnectRequest(_ context.Context, policy *compiledPolicy, sandboxID string, req helperproto.ConnectRequest) *helperproto.ConnectResponse {
	host, port := normalizeHostPort(req.Host, req.Port)
	var eval policyEvaluation
	if req.Transparent {
		eval = policy.evaluateConnect(req.Host, req.Port, true)
	} else {
		eval = policy.evaluateConnect(req.Host, req.Port, false)
	}
	event := eventWithPolicyMetadata(accessEvent{
		SandboxID:          sandboxID,
		Kind:               connectAccessKind(req.Transparent),
		Protocol:           req.ProtocolMetadata.Protocol,
		ProtocolSource:     req.ProtocolMetadata.Source,
		ProtocolConfidence: req.ProtocolMetadata.Confidence,
		Host:               host,
		Port:               port,
		Method:             http.MethodConnect,
	}, s.policyMode, eval)

	if !eval.Allowed && s.policyMode != PolicyModeAudit {
		err := eval.firstReasonAsError()
		event.Allowed = false
		event.StatusCode = http.StatusForbidden
		event.Result = "denied"
		event.Error = err.Error()
		s.recordEvent(event)
		return &helperproto.ConnectResponse{
			StatusCode: http.StatusForbidden,
			Message:    "connect request denied",
			Error:      err.Error(),
		}
	}

	event.Allowed = true
	event.StatusCode = http.StatusOK
	event.Result = "allowed"
	s.recordEvent(event)
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
