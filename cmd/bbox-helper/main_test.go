package main

import "testing"

func TestParseFlagsAcceptsTrafficMode(t *testing.T) {
	if _, err := parseFlags([]string{"--traffic-mode", "transparent", "child-proxy"}); err != nil {
		t.Fatalf("parseFlags rejected traffic mode: %v", err)
	}
}
