package seccompnotify

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDecodeSockaddrIn(t *testing.T) {
	raw := mustSockaddrInet4(t, "1.2.3.4", 443)
	got, err := DecodeSockaddr(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "1.2.3.4" || got.Port != 443 {
		t.Fatalf("got %#v", got)
	}
}

func TestDecodeSockaddrIn6(t *testing.T) {
	raw := mustSockaddrInet6(t, "2001:db8::1", 8443)
	got, err := DecodeSockaddr(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "2001:db8::1" || got.Port != 8443 {
		t.Fatalf("got %#v", got)
	}
}

func TestDecodeSockaddrShortBuffer(t *testing.T) {
	if _, err := DecodeSockaddr([]byte{0x02}); err == nil {
		t.Fatal("expected short buffer error")
	}
}

func mustSockaddrInet4(t *testing.T, host string, port int) []byte {
	t.Helper()

	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatalf("invalid IPv4 host %q", host)
	}
	if port < 0 || port > 65535 {
		t.Fatalf("invalid port %d", port)
	}

	raw := make([]byte, unix.SizeofSockaddrInet4)
	binary.LittleEndian.PutUint16(raw[0:2], uint16(unix.AF_INET))
	binary.BigEndian.PutUint16(raw[2:4], uint16(port))
	copy(raw[4:8], ip)
	return raw
}

func mustSockaddrInet6(t *testing.T, host string, port int) []byte {
	t.Helper()

	ip := net.ParseIP(host).To16()
	if ip == nil || ip.To4() != nil {
		t.Fatalf("invalid IPv6 host %q", host)
	}
	if port < 0 || port > 65535 {
		t.Fatalf("invalid port %d", port)
	}

	raw := make([]byte, unix.SizeofSockaddrInet6)
	binary.LittleEndian.PutUint16(raw[0:2], uint16(unix.AF_INET6))
	binary.BigEndian.PutUint16(raw[2:4], uint16(port))
	copy(raw[8:24], ip)
	return raw
}
