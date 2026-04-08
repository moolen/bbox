//go:build linux && cgo

package seccompnotify

import "testing"

func TestMinChildFDForSocketKindUsesSparseManagedBands(t *testing.T) {
	if got := minChildFDForSocketKind(KindTCP); got != 256 {
		t.Fatalf("tcp managed fd floor = %d, want 256", got)
	}
	if got := minChildFDForSocketKind(KindUDP); got != 512 {
		t.Fatalf("udp managed fd floor = %d, want 512", got)
	}
}

func TestMinDupFDForStateClampsManagedSocketKinds(t *testing.T) {
	tests := []struct {
		name         string
		state        SocketState
		requestedMin int
		want         int
	}{
		{
			name:         "tcp uses sparse tcp floor",
			state:        SocketState{Kind: KindTCP},
			requestedMin: 0,
			want:         256,
		},
		{
			name:         "udp uses sparse udp floor",
			state:        SocketState{Kind: KindUDP},
			requestedMin: 0,
			want:         512,
		},
		{
			name:         "requested minimum above floor wins",
			state:        SocketState{Kind: KindTCP},
			requestedMin: 300,
			want:         300,
		},
		{
			name:         "unknown leaves requested minimum untouched",
			state:        SocketState{Kind: KindUnknown},
			requestedMin: 17,
			want:         17,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := minDupFDForState(tc.state, tc.requestedMin); got != tc.want {
				t.Fatalf("minDupFDForState(%q, %d) = %d, want %d", tc.state.Kind, tc.requestedMin, got, tc.want)
			}
		})
	}
}
