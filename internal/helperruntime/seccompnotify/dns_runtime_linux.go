//go:build linux && cgo

package seccompnotify

import (
	"context"
	"errors"
	"net"
	"strings"
	"unsafe"

	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

const maxDNSPacketSize = 64 * 1024

type rawMmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
	_   uint32
}

func (s *Supervisor) emulateDNSSendTo(pid int, req *seccomp.ScmpNotifReq) (int, bool, error) {
	state, ok := s.lookupManagedUDPSocket(pid, req)
	if !ok {
		return 0, false, nil
	}

	payload, err := readProcessPayload(pid, uintptr(req.Data.Args[1]), int(req.Data.Args[2]))
	if err != nil {
		return 0, true, err
	}
	destination, isDNS, err := resolveDNSDestination(pid, state, uintptr(req.Data.Args[4]), int(req.Data.Args[5]))
	if err != nil {
		return 0, true, err
	}
	if !isDNS {
		return 0, false, nil
	}
	reply, err := s.dnsRoundTrip(destination, payload)
	if err != nil {
		return 0, true, err
	}

	state.DNSManaged = true
	state.PendingDNSResponses = append(state.PendingDNSResponses, dnsPacketResponse{
		Payload: reply,
		Source:  destination,
	})
	s.registry.Insert(state)
	return len(payload), true, nil
}

func (s *Supervisor) emulateDNSRead(pid int, req *seccomp.ScmpNotifReq) (int, bool, error) {
	state, ok := s.lookupManagedUDPSocket(pid, req)
	if !ok {
		return 0, false, nil
	}

	resp, err := takePendingDNSResponse(state, 0)
	if err != nil {
		return 0, true, err
	}

	n, err := writeProcessPayload(pid, uintptr(req.Data.Args[1]), int(req.Data.Args[2]), resp.Payload)
	if err != nil {
		return 0, true, err
	}

	state.PendingDNSResponses = state.PendingDNSResponses[1:]
	s.registry.Insert(state)
	return n, true, nil
}

func (s *Supervisor) emulateDNSRecvFrom(pid int, req *seccomp.ScmpNotifReq) (int, bool, error) {
	state, ok := s.lookupManagedUDPSocket(pid, req)
	if !ok {
		return 0, false, nil
	}

	flags := int(req.Data.Args[3])
	resp, err := takePendingDNSResponse(state, flags)
	if err != nil {
		return 0, true, err
	}

	n, err := writeProcessPayload(pid, uintptr(req.Data.Args[1]), int(req.Data.Args[2]), resp.Payload)
	if err != nil {
		return 0, true, err
	}
	if err := writeRecvfromSockaddr(pid, uintptr(req.Data.Args[4]), uintptr(req.Data.Args[5]), resp.Source); err != nil {
		return 0, true, err
	}

	if flags&unix.MSG_PEEK == 0 {
		state.PendingDNSResponses = state.PendingDNSResponses[1:]
		s.registry.Insert(state)
	}
	return n, true, nil
}

func (s *Supervisor) emulateDNSWrite(pid int, req *seccomp.ScmpNotifReq) (int, bool, error) {
	state, ok := s.lookupManagedUDPSocket(pid, req)
	if !ok {
		return 0, false, nil
	}

	payload, err := readProcessPayload(pid, uintptr(req.Data.Args[1]), int(req.Data.Args[2]))
	if err != nil {
		return 0, true, err
	}
	destination, isDNS, err := resolveDNSDestination(pid, state, 0, 0)
	if err != nil {
		return 0, true, err
	}
	if !isDNS {
		return 0, false, nil
	}
	reply, err := s.dnsRoundTrip(destination, payload)
	if err != nil {
		return 0, true, err
	}

	state.DNSManaged = true
	state.PendingDNSResponses = append(state.PendingDNSResponses, dnsPacketResponse{
		Payload: reply,
		Source:  destination,
	})
	s.registry.Insert(state)
	return len(payload), true, nil
}

func (s *Supervisor) emulateDNSSendMsg(pid int, req *seccomp.ScmpNotifReq) (int, bool, error) {
	state, ok := s.lookupManagedUDPSocket(pid, req)
	if !ok {
		return 0, false, nil
	}

	msg, err := readProcessValue[unix.Msghdr](pid, uintptr(req.Data.Args[1]))
	if err != nil {
		return 0, true, err
	}
	if msg.Control != nil && msg.Controllen > 0 {
		return 0, true, unix.EOPNOTSUPP
	}

	payload, err := readPayloadFromIovecs(pid, msg.Iov, int(msg.Iovlen))
	if err != nil {
		return 0, true, err
	}
	destination, isDNS, err := resolveDNSDestination(pid, state, uintptr(unsafe.Pointer(msg.Name)), int(msg.Namelen))
	if err != nil {
		return 0, true, err
	}
	if !isDNS {
		return 0, false, nil
	}
	reply, err := s.dnsRoundTrip(destination, payload)
	if err != nil {
		return 0, true, err
	}

	state.DNSManaged = true
	state.PendingDNSResponses = append(state.PendingDNSResponses, dnsPacketResponse{
		Payload: reply,
		Source:  destination,
	})
	s.registry.Insert(state)
	return len(payload), true, nil
}

func (s *Supervisor) emulateDNSRecvMsg(pid int, req *seccomp.ScmpNotifReq) (int, bool, error) {
	state, ok := s.lookupManagedUDPSocket(pid, req)
	if !ok {
		return 0, false, nil
	}

	msgAddr := uintptr(req.Data.Args[1])
	flags := int(req.Data.Args[2])
	msg, err := readProcessValue[unix.Msghdr](pid, msgAddr)
	if err != nil {
		return 0, true, err
	}

	resp, err := takePendingDNSResponse(state, flags)
	if err != nil {
		return 0, true, err
	}

	n, truncated, err := writePayloadToIovecs(pid, msg.Iov, int(msg.Iovlen), resp.Payload)
	if err != nil {
		return 0, true, err
	}
	if err := writeMsghdrSockaddr(pid, &msg, resp.Source); err != nil {
		return 0, true, err
	}
	msg.SetControllen(0)
	msg.Flags = 0
	if truncated {
		msg.Flags |= unix.MSG_TRUNC
	}
	if err := writeProcessValue(pid, msgAddr, msg); err != nil {
		return 0, true, err
	}

	if flags&unix.MSG_PEEK == 0 {
		state.PendingDNSResponses = state.PendingDNSResponses[1:]
		s.registry.Insert(state)
	}
	return n, true, nil
}

func (s *Supervisor) emulateDNSSendMMsg(pid int, req *seccomp.ScmpNotifReq) (int, bool, error) {
	state, ok := s.lookupManagedUDPSocket(pid, req)
	if !ok {
		return 0, false, nil
	}

	msgCount := int(req.Data.Args[2])
	if msgCount < 0 {
		return 0, true, unix.EINVAL
	}
	msgs, err := readProcessValues[rawMmsghdr](pid, uintptr(req.Data.Args[1]), msgCount)
	if err != nil {
		return 0, true, err
	}

	sent := 0
	for idx, msg := range msgs {
		if msg.Hdr.Control != nil && msg.Hdr.Controllen > 0 {
			if sent > 0 {
				return sent, true, nil
			}
			return 0, true, unix.EOPNOTSUPP
		}

		payload, readErr := readPayloadFromIovecs(pid, msg.Hdr.Iov, int(msg.Hdr.Iovlen))
		if readErr != nil {
			if sent > 0 {
				return sent, true, nil
			}
			return 0, true, readErr
		}
		destination, isDNS, resolveErr := resolveDNSDestination(pid, state, uintptr(unsafe.Pointer(msg.Hdr.Name)), int(msg.Hdr.Namelen))
		if resolveErr != nil {
			if sent > 0 {
				return sent, true, nil
			}
			return 0, true, resolveErr
		}
		if !isDNS {
			if sent > 0 {
				return sent, true, nil
			}
			return 0, false, nil
		}
		reply, roundTripErr := s.dnsRoundTrip(destination, payload)
		if roundTripErr != nil {
			if sent > 0 {
				return sent, true, nil
			}
			return 0, true, roundTripErr
		}

		state.DNSManaged = true
		state.PendingDNSResponses = append(state.PendingDNSResponses, dnsPacketResponse{
			Payload: reply,
			Source:  destination,
		})
		msg.Len = uint32(len(payload))
		if err := writeProcessValue(pid, uintptr(req.Data.Args[1])+uintptr(idx)*unsafe.Sizeof(rawMmsghdr{}), msg); err != nil {
			if sent > 0 {
				return sent, true, nil
			}
			return 0, true, err
		}
		sent++
	}
	s.registry.Insert(state)
	return sent, true, nil
}

func (s *Supervisor) emulateDNSRecvMMsg(pid int, req *seccomp.ScmpNotifReq) (int, bool, error) {
	state, ok := s.lookupManagedUDPSocket(pid, req)
	if !ok {
		return 0, false, nil
	}

	msgVecAddr := uintptr(req.Data.Args[1])
	msgCount := int(req.Data.Args[2])
	flags := int(req.Data.Args[3])
	if msgCount < 0 {
		return 0, true, unix.EINVAL
	}
	msgs, err := readProcessValues[rawMmsghdr](pid, msgVecAddr, msgCount)
	if err != nil {
		return 0, true, err
	}

	available := len(state.PendingDNSResponses)
	if available == 0 {
		return 0, true, unix.EAGAIN
	}

	received := 0
	peek := flags&unix.MSG_PEEK != 0
	for received < len(msgs) && received < available {
		resp := state.PendingDNSResponses[received]
		msg := msgs[received]

		n, truncated, writeErr := writePayloadToIovecs(pid, msg.Hdr.Iov, int(msg.Hdr.Iovlen), resp.Payload)
		if writeErr != nil {
			if received > 0 {
				break
			}
			return 0, true, writeErr
		}
		if err := writeMsghdrSockaddr(pid, &msg.Hdr, resp.Source); err != nil {
			if received > 0 {
				break
			}
			return 0, true, err
		}
		msg.Hdr.SetControllen(0)
		msg.Hdr.Flags = 0
		if truncated {
			msg.Hdr.Flags |= unix.MSG_TRUNC
		}
		msg.Len = uint32(n)
		if err := writeProcessValue(pid, msgVecAddr+uintptr(received)*unsafe.Sizeof(rawMmsghdr{}), msg); err != nil {
			if received > 0 {
				break
			}
			return 0, true, err
		}
		received++
	}
	if received == 0 {
		return 0, true, unix.EAGAIN
	}
	if !peek {
		state.PendingDNSResponses = state.PendingDNSResponses[received:]
		s.registry.Insert(state)
	}
	return received, true, nil
}

func (s *Supervisor) emulateDNSPoll(pid int, req *seccomp.ScmpNotifReq) (int, bool, error) {
	return s.emulateDNSPollFDs(pid, uintptr(req.Data.Args[0]), int(req.Data.Args[1]))
}

func (s *Supervisor) emulateDNSPPoll(pid int, req *seccomp.ScmpNotifReq) (int, bool, error) {
	return s.emulateDNSPollFDs(pid, uintptr(req.Data.Args[0]), int(req.Data.Args[1]))
}

// lookupManagedUDPSocket keeps DNS emulation scoped to sockets already under
// helper-managed UDP state.
func (s *Supervisor) emulateDNSPollFDs(pid int, fdsPtr uintptr, fdCount int) (int, bool, error) {
	if fdCount < 0 {
		return 0, true, unix.EINVAL
	}
	if fdCount == 0 {
		return 0, false, nil
	}

	pollFDs, err := readProcessValues[unix.PollFd](pid, fdsPtr, fdCount)
	if err != nil {
		return 0, true, err
	}

	ready := 0
	handled := false
	for idx := range pollFDs {
		pfd := &pollFDs[idx]
		if pfd.Fd < 0 {
			pfd.Revents = 0
			continue
		}
		state, ok := s.registry.LookupForPID(pid, int(pfd.Fd))
		if !ok || state.Kind != KindUDP || len(state.PendingDNSResponses) == 0 {
			pfd.Revents = 0
			continue
		}

		handled = true
		pfd.Revents = 0
		if pfd.Events&unix.POLLIN != 0 {
			pfd.Revents |= unix.POLLIN
		}
		if pfd.Events&unix.POLLOUT != 0 {
			pfd.Revents |= unix.POLLOUT
		}
		if pfd.Revents != 0 {
			ready++
		}
	}

	if !handled {
		return 0, false, nil
	}
	for idx, pfd := range pollFDs {
		if err := writeProcessValue(pid, fdsPtr+uintptr(idx)*unsafe.Sizeof(unix.PollFd{}), pfd); err != nil {
			return 0, true, err
		}
	}
	return ready, true, nil
}

func (s *Supervisor) dnsRoundTrip(destination DecodedSockaddr, payload []byte) ([]byte, error) {
	if s == nil || s.targets.DNSRoundTrip == nil {
		return nil, unix.EHOSTUNREACH
	}
	if destination.Port != 53 {
		return nil, unix.EPERM
	}
	payload = append([]byte(nil), payload...)
	reply, err := s.targets.DNSRoundTrip(context.Background(), "udp", destination.Host, destination.Port, payload)
	if err != nil {
		if errno, ok := dnsErrno(err); ok {
			return nil, errno
		}
		return nil, err
	}
	if len(reply) > maxDNSPacketSize {
		return nil, unix.EMSGSIZE
	}
	return append([]byte(nil), reply...), nil
}

func resolveDNSDestination(pid int, state SocketState, addrPtr uintptr, addrLen int) (DecodedSockaddr, bool, error) {
	if addrPtr != 0 {
		if addrLen <= 0 || addrLen > maxSockaddrBytes {
			return DecodedSockaddr{}, false, unix.EINVAL
		}
		rawAddr, err := readProcessMemoryExact(pid, addrPtr, addrLen)
		if err != nil {
			return DecodedSockaddr{}, false, err
		}
		decoded, err := DecodeSockaddr(rawAddr)
		if err != nil {
			return DecodedSockaddr{}, false, err
		}
		if decoded.Port != 53 {
			return decoded, false, nil
		}
		return decoded, true, nil
	}

	if strings.TrimSpace(state.ConnectedHost) == "" || state.ConnectedPort <= 0 {
		return DecodedSockaddr{}, false, unix.EDESTADDRREQ
	}
	if state.ConnectedPort != 53 {
		return DecodedSockaddr{
			Family: peernameFamily(state.ConnectedHost, state.Family),
			Host:   state.ConnectedHost,
			Port:   state.ConnectedPort,
		}, false, nil
	}
	return DecodedSockaddr{
		Family: peernameFamily(state.ConnectedHost, state.Family),
		Host:   state.ConnectedHost,
		Port:   state.ConnectedPort,
	}, true, nil
}

func takePendingDNSResponse(state SocketState, flags int) (dnsPacketResponse, error) {
	if len(state.PendingDNSResponses) == 0 {
		return dnsPacketResponse{}, unix.EAGAIN
	}
	_ = flags
	return state.PendingDNSResponses[0], nil
}

func readProcessPayload(pid int, addr uintptr, length int) ([]byte, error) {
	if length < 0 || length > maxDNSPacketSize {
		return nil, unix.EMSGSIZE
	}
	if length == 0 {
		return []byte{}, nil
	}
	return readProcessMemoryExact(pid, addr, length)
}

func writeProcessPayload(pid int, addr uintptr, length int, payload []byte) (int, error) {
	if length < 0 {
		return 0, unix.EINVAL
	}
	if len(payload) == 0 || length == 0 {
		return 0, nil
	}
	if addr == 0 {
		return 0, unix.EFAULT
	}
	n := min(length, len(payload))
	if err := writeProcessMemoryExact(pid, addr, payload[:n]); err != nil {
		return 0, err
	}
	return n, nil
}

func readPayloadFromIovecs(pid int, iovPtr *unix.Iovec, iovLen int) ([]byte, error) {
	if iovLen < 0 {
		return nil, unix.EINVAL
	}
	if iovLen == 0 {
		return []byte{}, nil
	}
	if iovPtr == nil {
		return nil, unix.EFAULT
	}
	iovecs, err := readProcessValues[unix.Iovec](pid, uintptr(unsafe.Pointer(iovPtr)), iovLen)
	if err != nil {
		return nil, err
	}

	total := 0
	for _, iov := range iovecs {
		if iov.Len > maxDNSPacketSize || total+int(iov.Len) > maxDNSPacketSize {
			return nil, unix.EMSGSIZE
		}
		total += int(iov.Len)
	}

	payload := make([]byte, 0, total)
	for _, iov := range iovecs {
		if iov.Len == 0 {
			continue
		}
		chunk, err := readProcessMemoryExact(pid, uintptr(unsafe.Pointer(iov.Base)), int(iov.Len))
		if err != nil {
			return nil, err
		}
		payload = append(payload, chunk...)
	}
	return payload, nil
}

func writePayloadToIovecs(pid int, iovPtr *unix.Iovec, iovLen int, payload []byte) (int, bool, error) {
	if iovLen < 0 {
		return 0, false, unix.EINVAL
	}
	if iovLen == 0 {
		return 0, len(payload) > 0, nil
	}
	if iovPtr == nil {
		return 0, false, unix.EFAULT
	}
	iovecs, err := readProcessValues[unix.Iovec](pid, uintptr(unsafe.Pointer(iovPtr)), iovLen)
	if err != nil {
		return 0, false, err
	}

	written := 0
	for _, iov := range iovecs {
		if written >= len(payload) {
			break
		}
		if iov.Len == 0 {
			continue
		}
		toWrite := min(int(iov.Len), len(payload)-written)
		if toWrite == 0 {
			continue
		}
		if err := writeProcessMemoryExact(pid, uintptr(unsafe.Pointer(iov.Base)), payload[written:written+toWrite]); err != nil {
			return 0, false, err
		}
		written += toWrite
	}
	return written, written < len(payload), nil
}

func writeRecvfromSockaddr(pid int, addrPtr, addrLenPtr uintptr, source DecodedSockaddr) error {
	if addrPtr == 0 && addrLenPtr == 0 {
		return nil
	}
	if addrPtr == 0 || addrLenPtr == 0 {
		return unix.EFAULT
	}
	return writeSockaddr(pid, addrPtr, addrLenPtr, source)
}

func writeMsghdrSockaddr(pid int, msg *unix.Msghdr, source DecodedSockaddr) error {
	if msg == nil || msg.Name == nil || msg.Namelen == 0 {
		return nil
	}
	raw, actualLen, err := encodeRawSockaddr(source)
	if err != nil {
		return err
	}
	copyLen := min(int(msg.Namelen), len(raw))
	if copyLen > 0 {
		if err := writeProcessMemoryExact(pid, uintptr(unsafe.Pointer(msg.Name)), raw[:copyLen]); err != nil {
			return err
		}
	}
	msg.Namelen = uint32(actualLen)
	return nil
}

func writeSockaddr(pid int, addrPtr, addrLenPtr uintptr, source DecodedSockaddr) error {
	raw, actualLen, err := encodeRawSockaddr(source)
	if err != nil {
		return err
	}

	suppliedLen, err := readProcessValue[uint32](pid, addrLenPtr)
	if err != nil {
		return err
	}
	copyLen := min(int(suppliedLen), len(raw))
	if copyLen > 0 {
		if err := writeProcessMemoryExact(pid, addrPtr, raw[:copyLen]); err != nil {
			return err
		}
	}
	return writeProcessValue(pid, addrLenPtr, uint32(actualLen))
}

func encodeRawSockaddr(source DecodedSockaddr) ([]byte, int, error) {
	ip := net.ParseIP(source.Host)
	if ip == nil {
		return nil, 0, unix.EINVAL
	}

	switch source.Family {
	case unix.AF_INET:
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, 0, unix.EAFNOSUPPORT
		}
		raw := make([]byte, unix.SizeofSockaddrInet4)
		putNativeUint16(raw[0:2], uint16(unix.AF_INET))
		putBigEndianUint16(raw[2:4], uint16(source.Port))
		copy(raw[4:8], ip4)
		return raw, len(raw), nil
	case unix.AF_INET6:
		ip6 := ip.To16()
		if ip6 == nil {
			return nil, 0, unix.EAFNOSUPPORT
		}
		raw := make([]byte, unix.SizeofSockaddrInet6)
		putNativeUint16(raw[0:2], uint16(unix.AF_INET6))
		putBigEndianUint16(raw[2:4], uint16(source.Port))
		copy(raw[8:24], ip6)
		return raw, len(raw), nil
	}

	if ip4 := ip.To4(); ip4 != nil {
		raw := make([]byte, unix.SizeofSockaddrInet4)
		putNativeUint16(raw[0:2], uint16(unix.AF_INET))
		putBigEndianUint16(raw[2:4], uint16(source.Port))
		copy(raw[4:8], ip4)
		return raw, len(raw), nil
	}
	if ip6 := ip.To16(); ip6 != nil {
		raw := make([]byte, unix.SizeofSockaddrInet6)
		putNativeUint16(raw[0:2], uint16(unix.AF_INET6))
		putBigEndianUint16(raw[2:4], uint16(source.Port))
		copy(raw[8:24], ip6)
		return raw, len(raw), nil
	}
	return nil, 0, unix.EINVAL
}

func readProcessMemoryExact(pid int, addr uintptr, size int) ([]byte, error) {
	if size < 0 {
		return nil, unix.EINVAL
	}
	if size == 0 {
		return []byte{}, nil
	}
	if addr == 0 {
		return nil, unix.EFAULT
	}
	data, err := readProcessMemory(pid, addr, size)
	if err != nil {
		return nil, err
	}
	if len(data) != size {
		return nil, unix.EFAULT
	}
	return data, nil
}

func writeProcessMemoryExact(pid int, addr uintptr, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if pid <= 0 {
		return unix.EINVAL
	}
	if addr == 0 {
		return unix.EFAULT
	}

	local := []unix.Iovec{{Base: &data[0]}}
	local[0].SetLen(len(data))
	remote := []unix.RemoteIovec{{Base: addr, Len: len(data)}}
	n, err := unix.ProcessVMWritev(pid, local, remote, 0)
	if err != nil {
		return err
	}
	if n != len(data) {
		return unix.EFAULT
	}
	return nil
}

func readProcessValue[T any](pid int, addr uintptr) (T, error) {
	var zero T
	size := int(unsafe.Sizeof(zero))
	if size == 0 {
		return zero, nil
	}
	data, err := readProcessMemoryExact(pid, addr, size)
	if err != nil {
		return zero, err
	}
	return *(*T)(unsafe.Pointer(&data[0])), nil
}

func readProcessValues[T any](pid int, addr uintptr, count int) ([]T, error) {
	var zero T
	if count < 0 {
		return nil, unix.EINVAL
	}
	if count == 0 {
		return nil, nil
	}
	size := int(unsafe.Sizeof(zero))
	if size == 0 {
		return make([]T, count), nil
	}
	data, err := readProcessMemoryExact(pid, addr, size*count)
	if err != nil {
		return nil, err
	}
	values := make([]T, count)
	for i := 0; i < count; i++ {
		offset := i * size
		values[i] = *(*T)(unsafe.Pointer(&data[offset]))
	}
	return values, nil
}

func writeProcessValue[T any](pid int, addr uintptr, value T) error {
	size := int(unsafe.Sizeof(value))
	if size == 0 {
		return nil
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(&value)), size)
	return writeProcessMemoryExact(pid, addr, data)
}

func dnsErrno(err error) (unix.Errno, bool) {
	var errno unix.Errno
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "denied") {
		return unix.EACCES, true
	}
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "not registered") {
		return unix.EHOSTUNREACH, true
	}
	if err != nil && errors.As(err, &errno) && errno != 0 {
		return errno, true
	}
	return 0, false
}

func putNativeUint16(dst []byte, value uint16) {
	if isLittleEndian() {
		dst[0] = byte(value)
		dst[1] = byte(value >> 8)
		return
	}
	dst[0] = byte(value >> 8)
	dst[1] = byte(value)
}

func putBigEndianUint16(dst []byte, value uint16) {
	dst[0] = byte(value >> 8)
	dst[1] = byte(value)
}

func isLittleEndian() bool {
	var value uint16 = 1
	return *(*byte)(unsafe.Pointer(&value)) == 1
}
