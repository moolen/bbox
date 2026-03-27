package bbox

import (
	"context"
	"encoding/gob"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/moolen/bbox/internal/helperproto"
)

func TestHelperClientRunSendFailureDoesNotWedgeFutureRuns(t *testing.T) {
	client := newHelperClient(nil, "sandbox-a", failingConn{writeErr: errors.New("write failed")})

	_, err := client.Run(context.Background(), []string{"/bin/echo", "first"}, RunOptions{})
	if err == nil || !strings.Contains(err.Error(), "send exec request") {
		t.Fatalf("expected send failure, got %v", err)
	}

	_, err = client.Run(context.Background(), []string{"/bin/echo", "second"}, RunOptions{})
	if err == nil {
		t.Fatal("expected second run to fail")
	}
	if strings.Contains(err.Error(), "already running") {
		t.Fatalf("expected client to clear busy state after send failure, got %v", err)
	}
}

func TestHelperClientRunPropagatesExecResultError(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	client := newHelperClient(nil, "sandbox-a", clientSide)

	go func() {
		client.loopDone <- client.readLoop()
	}()

	serverErrCh := make(chan error, 1)
	go func() {
		dec := gob.NewDecoder(serverSide)
		enc := gob.NewEncoder(serverSide)

		var req helperproto.Envelope
		if err := dec.Decode(&req); err != nil {
			serverErrCh <- err
			return
		}
		if req.ExecRequest == nil {
			serverErrCh <- errors.New("expected exec request")
			return
		}

		serverErrCh <- enc.Encode(&helperproto.Envelope{
			ID: req.ID,
			ExecResult: &helperproto.ExecResult{
				ExitCode: -1,
				Stderr:   []byte("stderr text"),
				Error:    "exec failed",
			},
		})
	}()

	result, err := client.Run(context.Background(), []string{"/bin/echo", "hello"}, RunOptions{})
	if err == nil || !strings.Contains(err.Error(), "exec failed") {
		t.Fatalf("expected exec result error to be returned, got %v", err)
	}
	if result == nil {
		t.Fatal("expected run result to be returned alongside the error")
	}
	if result.ExitCode != -1 {
		t.Fatalf("unexpected exit code: got %d", result.ExitCode)
	}
	if got := string(result.Stderr); got != "stderr text" {
		t.Fatalf("unexpected stderr: got %q", got)
	}

	if err := <-serverErrCh; err != nil {
		t.Fatalf("server side failed: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}
	if err := serverSide.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("close server side: %v", err)
	}
}

type failingConn struct {
	writeErr error
}

func (c failingConn) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (c failingConn) Write([]byte) (int, error) {
	return 0, c.writeErr
}

func (c failingConn) Close() error {
	return nil
}
