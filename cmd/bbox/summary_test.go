package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/moolen/bbox"
)

func TestRenderAccessSummaryIncludesHostsAndRequests(t *testing.T) {
	var buf bytes.Buffer
	renderAccessSummary(&buf, bbox.AccessSummary{
		Hosts:    []bbox.AccessedHostSummary{{Host: "example.com", Attempts: 2, LastPort: 443}},
		Requests: []bbox.RequestAggregate{{Kind: "mitm", Host: "example.com", Port: 443, Method: "GET", Path: "/ok", Attempts: 2}},
	})
	if !strings.Contains(buf.String(), "example.com") {
		t.Fatalf("missing host summary: %q", buf.String())
	}
}
