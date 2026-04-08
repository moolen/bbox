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

func TestRegistryScopesFDsByPID(t *testing.T) {
	reg := NewFDRegistry()
	reg.InsertForPID(101, SocketState{ChildFD: 8, Kind: KindTCP, OriginalHost: "child.example", OriginalPort: 443})
	reg.InsertForPID(202, SocketState{ChildFD: 8, Kind: KindUDP, OriginalHost: "parent.example", OriginalPort: 53})

	child, ok := reg.LookupForPID(101, 8)
	if !ok {
		t.Fatal("expected child pid fd state")
	}
	if child.OriginalHost != "child.example" || child.Kind != KindTCP {
		t.Fatalf("unexpected child state: %#v", child)
	}

	parent, ok := reg.LookupForPID(202, 8)
	if !ok {
		t.Fatal("expected parent pid fd state")
	}
	if parent.OriginalHost != "parent.example" || parent.Kind != KindUDP {
		t.Fatalf("unexpected parent state: %#v", parent)
	}
}
