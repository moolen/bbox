package bbox

import (
	"net/http"
	"testing"
	"time"
)

func TestAccessSummaryAggregatesRequestsByKindHostPortMethodPath(t *testing.T) {
	state := map[string]*requestAggregateState{}
	firstSeen := time.Date(2026, 3, 31, 10, 0, 0, 0, time.UTC)
	lastSeen := firstSeen.Add(time.Minute)

	recordRequestAggregate(state, accessEvent{
		Time:          firstSeen,
		Kind:          "mitm",
		Host:          "example.com",
		Port:          443,
		Method:        http.MethodGet,
		Path:          "/v1/data",
		Allowed:       true,
		PolicyAllowed: false,
		StatusCode:    http.StatusForbidden,
		Error:         "method GET is not allowed",
	})
	recordRequestAggregate(state, accessEvent{
		Time:          lastSeen,
		Kind:          "mitm",
		Host:          "example.com",
		Port:          443,
		Method:        http.MethodGet,
		Path:          "/v1/data",
		Allowed:       true,
		PolicyAllowed: true,
		StatusCode:    http.StatusOK,
	})

	snapshot := snapshotRequestAggregates(state)
	if len(snapshot) != 1 {
		t.Fatalf("expected one aggregate, got %d", len(snapshot))
	}

	aggregate := snapshot[0]
	if aggregate.Kind != "mitm" || aggregate.Host != "example.com" || aggregate.Port != 443 {
		t.Fatalf("unexpected aggregate identity: %#v", aggregate)
	}
	if aggregate.Method != http.MethodGet || aggregate.Path != "/v1/data" {
		t.Fatalf("unexpected aggregate method/path: %#v", aggregate)
	}
	if aggregate.Attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", aggregate.Attempts)
	}
	if aggregate.AllowedCount != 2 {
		t.Fatalf("expected 2 allowed attempts, got %d", aggregate.AllowedCount)
	}
	if aggregate.DeniedCount != 0 {
		t.Fatalf("expected 0 denied attempts, got %d", aggregate.DeniedCount)
	}
	if aggregate.PolicyAllowedCount != 1 {
		t.Fatalf("expected 1 policy-allowed attempt, got %d", aggregate.PolicyAllowedCount)
	}
	if aggregate.PolicyDeniedCount != 1 {
		t.Fatalf("expected 1 policy-denied attempt, got %d", aggregate.PolicyDeniedCount)
	}
	if !aggregate.LastSeenAt.Equal(lastSeen) {
		t.Fatalf("expected last seen %v, got %v", lastSeen, aggregate.LastSeenAt)
	}
	if aggregate.LastStatusCode != http.StatusOK {
		t.Fatalf("expected last status code %d, got %d", http.StatusOK, aggregate.LastStatusCode)
	}
	if aggregate.LastError != "" {
		t.Fatalf("expected last error to be cleared, got %q", aggregate.LastError)
	}
}
