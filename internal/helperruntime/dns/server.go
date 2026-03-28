package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const maxTCPPayloadSize = 4 << 10

const tcpConnDeadline = 5 * time.Second

type Server struct {
	tcpListener net.Listener
	udpConn     net.PacketConn
}

func NewServer(addr string) (*Server, error) {
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	udpAddr, err := udpAddr(tcpListener.Addr())
	if err != nil {
		_ = tcpListener.Close()
		return nil, err
	}

	udpConn, err := net.ListenPacket("udp", udpAddr)
	if err != nil {
		_ = tcpListener.Close()
		return nil, err
	}

	return &Server{
		tcpListener: tcpListener,
		udpConn:     udpConn,
	}, nil
}

func udpAddr(addr net.Addr) (string, error) {
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", fmt.Errorf("split DNS listener address %q: %w", addr.String(), err)
	}

	return net.JoinHostPort(host, port), nil
}

func (s *Server) Addr() string {
	return s.tcpListener.Addr().String()
}

func (s *Server) Close() error {
	var errs []error
	if s.udpConn != nil {
		if err := s.udpConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	if s.tcpListener != nil {
		if err := s.tcpListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func (s *Server) Serve() error {
	errCh := make(chan error, 2)

	go func() {
		errCh <- serveUDP(s.udpConn)
	}()
	go func() {
		errCh <- serveTCP(s.tcpListener)
	}()

	err := <-errCh
	if err != nil {
		_ = s.Close()
	}

	return err
}

func serveUDP(conn net.PacketConn) error {
	buf := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return err
		}

		response, ok := HandleQuery(buf[:n])
		if !ok {
			continue
		}
		if _, err := conn.WriteTo(response, addr); err != nil {
			return err
		}
	}
}

func serveTCP(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		go func() {
			_ = serveTCPConn(conn)
		}()
	}
}

func serveTCPConn(conn net.Conn) error {
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(tcpConnDeadline)); err != nil {
		return err
	}

	var lengthBuf [2]byte
	if _, err := io.ReadFull(conn, lengthBuf[:]); err != nil {
		return err
	}

	queryLen := int(binary.BigEndian.Uint16(lengthBuf[:]))
	if queryLen > maxTCPPayloadSize {
		return fmt.Errorf("dns tcp payload length %d exceeds maximum %d", queryLen, maxTCPPayloadSize)
	}

	query := make([]byte, queryLen)
	if _, err := io.ReadFull(conn, query); err != nil {
		return err
	}

	response, ok := HandleQuery(query)
	if !ok {
		return nil
	}

	frame := make([]byte, 2+len(response))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(response)))
	copy(frame[2:], response)
	_, err := conn.Write(frame)
	return err
}

func HandleQuery(payload []byte) ([]byte, bool) {
	var parser dnsmessage.Parser
	header, err := parser.Start(payload)
	if err != nil {
		return nil, false
	}

	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 {
		return nil, false
	}

	response := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 header.ID,
			Response:           true,
			OpCode:             header.OpCode,
			Authoritative:      true,
			RecursionDesired:   header.RecursionDesired,
			RecursionAvailable: false,
		},
		Questions: questions,
	}

	question := questions[0]
	if question.Class != dnsmessage.ClassINET {
		response.Header.RCode = dnsmessage.RCodeRefused
	} else {
		switch question.Type {
		case dnsmessage.TypeA:
			response.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name:  question.Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
			}}
		case dnsmessage.TypeAAAA:
		default:
			response.Header.RCode = dnsmessage.RCodeRefused
		}
	}

	packed, err := response.Pack()
	if err != nil {
		return nil, false
	}

	return packed, true
}
