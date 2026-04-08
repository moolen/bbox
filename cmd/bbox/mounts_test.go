package main

import (
	"strings"
	"testing"

	"github.com/moolen/bbox"
)

func TestParseCLIMountSpecBindReadOnly(t *testing.T) {
	got, err := parseCLIMountSpec("type=bind,source=/host,target=/sandbox,read-only")
	if err != nil {
		t.Fatal(err)
	}
	want := bbox.Mount{
		Type:     bbox.MountTypeBind,
		Source:   "/host",
		Target:   "/sandbox",
		ReadOnly: true,
	}
	if got != want {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestParseCLIMountSpecBindReadWrite(t *testing.T) {
	got, err := parseCLIMountSpec("type=bind,source=/host,target=/sandbox")
	if err != nil {
		t.Fatal(err)
	}
	want := bbox.Mount{
		Type:   bbox.MountTypeBind,
		Source: "/host",
		Target: "/sandbox",
	}
	if got != want {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestParseCLIMountSpecEmptyDir(t *testing.T) {
	got, err := parseCLIMountSpec("type=empty_dir,target=/var/lib/buildkit,mode=0755")
	if err != nil {
		t.Fatal(err)
	}
	want := bbox.Mount{
		Type:   bbox.MountTypeEmptyDir,
		Target: "/var/lib/buildkit",
		Mode:   0o755,
	}
	if got != want {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestParseCLIMountSpecRejectsUnknownKey(t *testing.T) {
	_, err := parseCLIMountSpec("type=bind,source=/host,target=/sandbox,nope=value")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unknown mount key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseCLIMountSpecRejectsUnknownType(t *testing.T) {
	_, err := parseCLIMountSpec("type=tmpfs,target=/tmp")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unknown mount type") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseCLIMountSpecRejectsEmptyDirSource(t *testing.T) {
	_, err := parseCLIMountSpec("type=empty_dir,source=/host,target=/tmp")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "empty_dir mount must not set source") {
		t.Fatalf("unexpected error: %v", err)
	}
}
