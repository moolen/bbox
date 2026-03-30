package main

import "testing"

func TestParseFlagsAcceptsTrafficMode(t *testing.T) {
	if _, err := parseFlags([]string{"--traffic-mode", "transparent", "child-proxy"}); err != nil {
		t.Fatalf("parseFlags rejected traffic mode: %v", err)
	}
}

func TestParseFlagsRejectsRemovedDNSAddrFlag(t *testing.T) {
	if _, err := parseFlags([]string{"--dns-addr", "127.0.0.1:53", "child-proxy"}); err == nil {
		t.Fatal("expected removed --dns-addr flag to be rejected")
	}
}
