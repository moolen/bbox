//go:build linux

package seccompnotify

import "testing"

func TestRegistryTracksManagedFDLifecycle(t *testing.T) {
	reg := NewFDRegistry()
	reg.Insert(SocketState{ChildFD: 7, Kind: KindTCP})
	if _, ok := reg.Lookup(7); !ok {
		t.Fatal("expected fd state")
	}

	reg.Close(7)
	if _, ok := reg.Lookup(7); ok {
		t.Fatal("expected fd state to be removed")
	}
}

func TestRegistryDuplicatesFDState(t *testing.T) {
	reg := NewFDRegistry()
	reg.Insert(SocketState{ChildFD: 5, OriginalHost: "api2.cursor.sh", OriginalPort: 443})

	if err := reg.Dup(5, 9); err != nil {
		t.Fatal(err)
	}

	got, ok := reg.Lookup(9)
	if !ok {
		t.Fatal("expected duplicated fd state")
	}
	if got.OriginalHost != "api2.cursor.sh" || got.OriginalPort != 443 {
		t.Fatalf("got %#v", got)
	}
}

func TestRegistryDupReplacesTargetFDState(t *testing.T) {
	reg := NewFDRegistry()
	reg.Insert(SocketState{ChildFD: 5, Kind: KindTCP, OriginalHost: "api2.cursor.sh", OriginalPort: 443})
	reg.Insert(SocketState{ChildFD: 9, Kind: KindTCP, OriginalHost: "old.example", OriginalPort: 80})

	if err := reg.Dup(5, 9); err != nil {
		t.Fatal(err)
	}

	got, ok := reg.Lookup(9)
	if !ok {
		t.Fatal("expected duplicated state at target fd")
	}
	if got.OriginalHost != "api2.cursor.sh" || got.OriginalPort != 443 {
		t.Fatalf("got %#v", got)
	}
}
