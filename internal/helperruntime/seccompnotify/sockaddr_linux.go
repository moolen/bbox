package seccompnotify

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func DecodeSockaddr(raw []byte) (DecodedSockaddr, error) {
	if len(raw) < 2 {
		return DecodedSockaddr{}, fmt.Errorf("sockaddr buffer too short: %d", len(raw))
	}

	family, err := decodeFamily(raw)
	if err != nil {
		return DecodedSockaddr{}, err
	}

	switch family {
	case unix.AF_INET:
		if len(raw) < unix.SizeofSockaddrInet4 {
			return DecodedSockaddr{}, fmt.Errorf("sockaddr_in buffer too short: %d", len(raw))
		}
		return DecodedSockaddr{
			Family: unix.AF_INET,
			Host:   net.IP(raw[4:8]).String(),
			Port:   int(binary.BigEndian.Uint16(raw[2:4])),
		}, nil
	case unix.AF_INET6:
		if len(raw) < unix.SizeofSockaddrInet6 {
			return DecodedSockaddr{}, fmt.Errorf("sockaddr_in6 buffer too short: %d", len(raw))
		}
		return DecodedSockaddr{
			Family: unix.AF_INET6,
			Host:   net.IP(raw[8:24]).String(),
			Port:   int(binary.BigEndian.Uint16(raw[2:4])),
		}, nil
	default:
		return DecodedSockaddr{}, fmt.Errorf("unsupported sockaddr family %d", family)
	}
}

func decodeFamily(raw []byte) (int, error) {
	if len(raw) < 2 {
		return 0, fmt.Errorf("sockaddr buffer too short: %d", len(raw))
	}

	familyLE := binary.LittleEndian.Uint16(raw[0:2])
	switch familyLE {
	case unix.AF_INET, unix.AF_INET6:
		return int(familyLE), nil
	}

	familyBE := binary.BigEndian.Uint16(raw[0:2])
	switch familyBE {
	case unix.AF_INET, unix.AF_INET6:
		return int(familyBE), nil
	}

	return 0, fmt.Errorf("unsupported sockaddr family encoding %d/%d", familyLE, familyBE)
}
