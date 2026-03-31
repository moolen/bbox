package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/moolen/bbox"
)

type cliAccessLogger struct {
	mu      sync.Mutex
	entries []bbox.AccessLogEntry
	enc     *json.Encoder
}

func newCLIAccessLogger(w io.Writer, emitJSON bool) *cliAccessLogger {
	logger := &cliAccessLogger{}
	if emitJSON && w != nil {
		logger.enc = json.NewEncoder(w)
	}
	return logger
}

func (l *cliAccessLogger) LogAccess(entry bbox.AccessLogEntry) {
	if l == nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.entries = append(l.entries, entry)
	if l.enc != nil {
		_ = l.enc.Encode(entry)
	}
}

func (l *cliAccessLogger) Entries() []bbox.AccessLogEntry {
	if l == nil {
		return []bbox.AccessLogEntry{}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entries := make([]bbox.AccessLogEntry, len(l.entries))
	copy(entries, l.entries)
	return entries
}

func renderRunSummary(w io.Writer, summary bbox.AccessSummary, entries []bbox.AccessLogEntry, reporting bbox.ReportingOptions) error {
	filtered := bbox.AccessSummary{}
	if reporting.AccessSummary {
		filtered.Hosts = summary.Hosts
	}
	if reporting.RequestSummary {
		filtered.Requests = summary.Requests
	}
	if err := renderAccessSummary(w, filtered); err != nil {
		return err
	}
	if reporting.PolicyViolations {
		if err := renderPolicyViolations(w, entries); err != nil {
			return err
		}
	}
	return nil
}

func renderAccessSummary(w io.Writer, summary bbox.AccessSummary) error {
	if w == nil {
		return nil
	}

	sections := 0
	if summary.Hosts != nil {
		if sections > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w, "Access summary"); err != nil {
			return err
		}
		if len(summary.Hosts) == 0 {
			if _, err := fmt.Fprintln(w, "  none"); err != nil {
				return err
			}
		}
		for _, host := range summary.Hosts {
			if _, err := fmt.Fprintf(w, "  %s: attempts=%d last_result=%s last_port=%d violations=%d\n",
				host.Host, host.Attempts, emptyValue(host.LastResult), host.LastPort, host.PolicyViolations); err != nil {
				return err
			}
		}
		sections++
	}

	if summary.Requests != nil {
		if sections > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w, "Request summary"); err != nil {
			return err
		}
		if len(summary.Requests) == 0 {
			if _, err := fmt.Fprintln(w, "  none"); err != nil {
				return err
			}
		}
		for _, req := range summary.Requests {
			if _, err := fmt.Fprintf(w, "  %s %s %s:%d %s attempts=%d allowed=%d denied=%d policy_allowed=%d policy_denied=%d\n",
				emptyValue(req.Kind),
				emptyValue(req.Method),
				req.Host,
				req.Port,
				emptyValue(req.Path),
				req.Attempts,
				req.AllowedCount,
				req.DeniedCount,
				req.PolicyAllowedCount,
				req.PolicyDeniedCount,
			); err != nil {
				return err
			}
		}
	}

	return nil
}

func renderPolicyViolations(w io.Writer, entries []bbox.AccessLogEntry) error {
	if w == nil {
		return nil
	}

	lines := make([]string, 0)
	for _, entry := range entries {
		if len(entry.PolicyViolations) == 0 {
			continue
		}
		violations := append([]string(nil), entry.PolicyViolations...)
		sort.Strings(violations)
		lines = append(lines, fmt.Sprintf(
			"  %s %s %s:%d %s violations=%s",
			emptyValue(entry.Kind),
			emptyValue(entry.Method),
			entry.Host,
			entry.Port,
			emptyValue(entry.Path),
			strings.Join(violations, "; "),
		))
	}
	sort.Strings(lines)

	if _, err := fmt.Fprintln(w, "Policy violations"); err != nil {
		return err
	}
	if len(lines) == 0 {
		_, err := fmt.Fprintln(w, "  none")
		return err
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

func emptyValue(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
