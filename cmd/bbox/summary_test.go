package main

import (
	"bytes"
	"io"
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

func TestCLIAccessLoggerBuffersJSONUntilFlush(t *testing.T) {
	var buf bytes.Buffer
	logger := newCLIAccessLogger(&buf, true)

	logger.LogAccess(bbox.AccessLogEntry{
		SandboxID: "sandbox-cli",
		Kind:      "http",
		Host:      "example.com",
		Port:      443,
	})

	if buf.Len() != 0 {
		t.Fatalf("expected cli logger to defer writes until flush, got %q", buf.String())
	}
}

func TestFinalizeRunOutputRestoresTerminalBeforeWriting(t *testing.T) {
	var order []string
	writer := &orderedWriter{beforeWrite: func() { order = append(order, "write") }}
	logger := newCLIAccessLogger(io.Discard, false)
	logger.LogAccess(bbox.AccessLogEntry{
		SandboxID: "sandbox-cli",
		Kind:      "http",
		Host:      "example.com",
		Port:      443,
	})

	err := finalizeRunOutput(func() {
		order = append(order, "cleanup")
	}, writer, logger, bbox.AccessSummary{
		Hosts: []bbox.AccessedHostSummary{{Host: "example.com", Attempts: 1, LastPort: 443}},
	}, bbox.ReportingOptions{AccessSummary: true})
	if err != nil {
		t.Fatal(err)
	}

	if len(order) < 2 {
		t.Fatalf("expected cleanup and write events, got %v", order)
	}
	if order[0] != "cleanup" || order[1] != "write" {
		t.Fatalf("expected cleanup before write, got %v", order)
	}
}

type orderedWriter struct {
	beforeWrite func()
}

func (w *orderedWriter) Write(p []byte) (int, error) {
	if w.beforeWrite != nil {
		w.beforeWrite()
	}
	return len(p), nil
}
