package helperclient

import (
	"bytes"
	"encoding/gob"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/moolen/bbox/internal/helperproto"
)

func TestRunSessionFinishIsSingleShot(t *testing.T) {
	session := NewRunSession(io.Discard, io.Discard)
	if !session.Finish(&RunResult{ExitCode: 0}, nil) {
		t.Fatal("first finish should win")
	}
	if session.Finish(&RunResult{ExitCode: 1}, errors.New("late")) {
		t.Fatal("second finish should be ignored")
	}
}

func TestTunnelWriteCloseSendsTerminalCloseOnce(t *testing.T) {
	client := New(nil, "sandbox-a", &recordingConn{})
	tunnel := NewHostTunnel(client, 7, nopConn{})
	tunnel.SendWriteClose(io.EOF)
	tunnel.SendWriteClose(io.EOF)
	if got := countTunnelCloseEnvelopes(client.conn.(*recordingConn).Bytes(), 7); got != 1 {
		t.Fatalf("expected 1 tunnel close envelope, got %d", got)
	}
}

type recordingConn struct {
	bytes.Buffer
}

func (c *recordingConn) Close() error { return nil }

type nopConn struct{}

func (nopConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (nopConn) Write(p []byte) (int, error)      { return len(p), nil }
func (nopConn) Close() error                     { return nil }
func (nopConn) LocalAddr() net.Addr              { return nil }
func (nopConn) RemoteAddr() net.Addr             { return nil }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }

func countTunnelCloseEnvelopes(frames []byte, id uint64) int {
	dec := gob.NewDecoder(bytes.NewReader(frames))
	count := 0
	for {
		var env helperproto.Envelope
		if err := dec.Decode(&env); err != nil {
			if errors.Is(err, io.EOF) {
				return count
			}
			return count
		}
		if env.ID == id && env.TunnelClose != nil {
			count++
		}
	}
}
