package bbox

import (
	"bytes"
	"errors"
	"io"
	"sync/atomic"

	"github.com/moolen/bbox/internal/helperproto"
)

type runSession struct {
	stdout       bytes.Buffer
	stderr       bytes.Buffer
	stdoutWriter io.Writer
	stderrWriter io.Writer
	resultCh     chan runOutcome
	finished     atomic.Bool
}

type runOutcome struct {
	result *RunResult
	err    error
}

func newRunSession(stdout, stderr io.Writer) *runSession {
	return &runSession{
		stdoutWriter: stdout,
		stderrWriter: stderr,
		resultCh:     make(chan runOutcome, 1),
	}
}

func (s *runSession) Finish(result *RunResult, err error) bool {
	if s == nil {
		return false
	}
	if !s.finished.CompareAndSwap(false, true) {
		return false
	}
	s.resultCh <- runOutcome{result: result, err: err}
	return true
}

func (s *runSession) HandleStream(frame helperproto.StreamFrame) {
	if s == nil {
		return
	}

	switch frame.Stream {
	case helperproto.StreamStdout:
		_, _ = s.stdout.Write(frame.Data)
		if s.stdoutWriter != nil {
			_, _ = s.stdoutWriter.Write(frame.Data)
		}
	case helperproto.StreamStderr:
		_, _ = s.stderr.Write(frame.Data)
		if s.stderrWriter != nil {
			_, _ = s.stderrWriter.Write(frame.Data)
		}
	}
}

func (s *runSession) HandleExecResult(result helperproto.ExecResult) bool {
	if s == nil {
		return false
	}

	stderr := append([]byte(nil), s.stderr.Bytes()...)
	if len(result.Stderr) > 0 {
		stderr = append(stderr, result.Stderr...)
		if s.stderrWriter != nil {
			_, _ = s.stderrWriter.Write(result.Stderr)
		}
	}

	return s.Finish(&RunResult{
		ExitCode: result.ExitCode,
		Stdout:   append([]byte(nil), s.stdout.Bytes()...),
		Stderr:   stderr,
	}, execResultError(result))
}

func (c *helperClient) installRunSession(session *runSession) error {
	c.currentMu.Lock()
	defer c.currentMu.Unlock()
	if c.currentRun != nil {
		return errors.New("another command is already running")
	}
	c.currentRun = session
	return nil
}

func (c *helperClient) currentRunSession() *runSession {
	c.currentMu.Lock()
	defer c.currentMu.Unlock()
	return c.currentRun
}

func (c *helperClient) clearCurrentRun() *runSession {
	c.currentMu.Lock()
	defer c.currentMu.Unlock()
	session := c.currentRun
	c.currentRun = nil
	return session
}

func (c *helperClient) handleStream(frame helperproto.StreamFrame) {
	session := c.currentRunSession()
	if session == nil {
		return
	}
	session.HandleStream(frame)
}

func (c *helperClient) handleExecResult(result helperproto.ExecResult) {
	session := c.clearCurrentRun()
	if session == nil {
		return
	}
	session.HandleExecResult(result)
}

func (c *helperClient) failCurrentRun(err error) {
	session := c.clearCurrentRun()
	if session == nil {
		return
	}
	session.Finish(nil, err)
}

func execResultError(result helperproto.ExecResult) error {
	if result.Error == "" {
		return nil
	}
	return errors.New(result.Error)
}

func (c *helperClient) pumpRunInput(id uint64, src io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if sendErr := c.send(helperproto.Envelope{
				ID: id,
				ExecInput: &helperproto.ExecInput{
					Data: append([]byte(nil), buf[:n]...),
				},
			}); sendErr != nil {
				return
			}
		}
		if errors.Is(err, io.EOF) {
			_ = c.send(helperproto.Envelope{
				ID: id,
				ExecInput: &helperproto.ExecInput{
					EOF: true,
				},
			})
			return
		}
		if err != nil {
			return
		}
	}
}

func (c *helperClient) pumpRunResize(id uint64, sizes <-chan TerminalSize) {
	for size := range sizes {
		if size.Rows == 0 && size.Cols == 0 {
			continue
		}
		if err := c.send(helperproto.Envelope{
			ID: id,
			ExecInput: &helperproto.ExecInput{
				Resize: &helperproto.TerminalSize{
					Rows: size.Rows,
					Cols: size.Cols,
				},
			},
		}); err != nil {
			return
		}
	}
}
