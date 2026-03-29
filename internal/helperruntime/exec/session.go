package hrexec

import (
	"errors"
	"io"
	"log"
	"os"
	stdexec "os/exec"
	"syscall"

	"github.com/creack/pty"
	"github.com/moolen/bbox/internal/helperproto"
)

type Session struct {
	cmd      *stdexec.Cmd
	stdin    io.WriteCloser
	ptyFile  *os.File
	terminal bool
}

type OutputStream struct {
	Stream helperproto.StreamType
	Reader io.Reader
}

type EnvelopeSender func(helperproto.Envelope) error

func StartSession(cmd *stdexec.Cmd, req helperproto.ExecRequest) (*Session, []OutputStream, error) {
	if req.Interactive && req.Terminal {
		size := &pty.Winsize{Rows: 24, Cols: 80}
		if req.InitialSize != nil {
			if req.InitialSize.Rows > 0 {
				size.Rows = req.InitialSize.Rows
			}
			if req.InitialSize.Cols > 0 {
				size.Cols = req.InitialSize.Cols
			}
		}
		ptmx, err := pty.StartWithSize(cmd, size)
		if err != nil {
			return nil, nil, err
		}
		return &Session{
				cmd:      cmd,
				stdin:    ptmx,
				ptyFile:  ptmx,
				terminal: true,
			}, []OutputStream{{
				Stream: helperproto.StreamStdout,
				Reader: ptmx,
			}}, nil
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, err
	}

	var session *Session
	if req.Interactive {
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return nil, nil, err
		}
		session = &Session{cmd: cmd, stdin: stdin}
	}

	if err := cmd.Start(); err != nil {
		if session != nil && session.stdin != nil {
			_ = session.stdin.Close()
		}
		return nil, nil, err
	}

	return session, []OutputStream{
		{Stream: helperproto.StreamStdout, Reader: stdout},
		{Stream: helperproto.StreamStderr, Reader: stderr},
	}, nil
}

func StreamOutput(id uint64, stream OutputStream, send EnvelopeSender, logger *log.Logger) {
	buf := make([]byte, 32*1024)
	for {
		n, err := stream.Reader.Read(buf)
		if n > 0 {
			if sendErr := send(helperproto.Envelope{
				ID: id,
				StreamFrame: &helperproto.StreamFrame{
					Stream: stream.Stream,
					Data:   append([]byte(nil), buf[:n]...),
				},
			}); sendErr != nil {
				if logger != nil {
					logger.Printf("send %s frame: %v", stream.Stream, sendErr)
				}
				return
			}
		}
		if errors.Is(err, io.EOF) {
			return
		}
		if errors.Is(err, syscall.EIO) {
			return
		}
		if err != nil {
			if logger != nil {
				logger.Printf("read %s stream: %v", stream.Stream, err)
			}
			return
		}
	}
}

func HandleInput(session *Session, input helperproto.ExecInput) {
	if session == nil {
		return
	}

	if input.Resize != nil && session.terminal && session.ptyFile != nil {
		if input.Resize.Rows > 0 || input.Resize.Cols > 0 {
			_ = pty.Setsize(session.ptyFile, &pty.Winsize{
				Rows: maxUint16(input.Resize.Rows, 24),
				Cols: maxUint16(input.Resize.Cols, 80),
			})
		}
	}

	if len(input.Data) > 0 && session.stdin != nil {
		if _, err := session.stdin.Write(input.Data); err != nil {
			return
		}
	}
	if input.EOF && session.stdin != nil && !session.terminal {
		_ = session.stdin.Close()
	}
}

func (s *Session) Close() error {
	if s == nil {
		return nil
	}

	var err error
	if s.ptyFile != nil {
		err = s.ptyFile.Close()
	}
	if s.stdin != nil {
		if file, ok := s.stdin.(*os.File); ok && file == s.ptyFile {
			return err
		}
		if closeErr := s.stdin.Close(); err == nil {
			err = closeErr
		}
	}
	return err
}

func maxUint16(value, fallback uint16) uint16 {
	if value == 0 {
		return fallback
	}
	return value
}
