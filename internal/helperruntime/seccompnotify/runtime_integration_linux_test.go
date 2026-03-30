//go:build linux

package seccompnotify

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSupervisorStartRedirectsTCPConnectRuntime(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	launcher := buildLauncherBinary(t)

	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw ingress: %v", err)
	}
	t.Cleanup(func() { _ = rawListener.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := rawListener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	restore := setLauncherCommandForTest(t, func() (string, []string, error) {
		return launcher, nil, nil
	})
	t.Cleanup(restore)

	s, err := NewSupervisor(RuntimeTargets{
		RawTCPAddr: rawListener.Addr().String(),
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			t.Fatalf("close supervisor: %v", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.Command(
		python,
		"-c",
		"import socket,sys; s=socket.create_connection((sys.argv[1], int(sys.argv[2])), 2); s.close()",
		"198.51.100.77",
		"8443",
	)
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	if err := s.Prepare(ctx, cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}

	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for redirected raw tcp accept")
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestSupervisorStartRedirectsConnectedUDPDNSRuntime(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	launcher := buildLauncherBinary(t)

	dnsConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dns ingress: %v", err)
	}
	t.Cleanup(func() { _ = dnsConn.Close() })

	query := []byte{0xde, 0xad, 0xbe, 0xef}
	reply := []byte{0xca, 0xfe, 0xba, 0xbe}
	serverErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 512)
		n, addr, readErr := dnsConn.ReadFrom(buf)
		if readErr != nil {
			serverErr <- readErr
			return
		}
		if !bytes.Equal(buf[:n], query) {
			serverErr <- fmt.Errorf("query=%x want=%x", buf[:n], query)
			return
		}
		_, writeErr := dnsConn.WriteTo(reply, addr)
		serverErr <- writeErr
	}()

	restore := setLauncherCommandForTest(t, func() (string, []string, error) {
		return launcher, nil, nil
	})
	t.Cleanup(restore)

	s, err := NewSupervisor(RuntimeTargets{
		DNSAddr: dnsConn.LocalAddr().String(),
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			t.Fatalf("close supervisor: %v", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.Command(
		python,
		"-c",
		"import socket,sys,binascii; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); s.connect((sys.argv[1], int(sys.argv[2]))); s.send(bytes.fromhex(sys.argv[3])); data=s.recv(512); sys.exit(0 if data == bytes.fromhex(sys.argv[4]) else 1)",
		"192.0.2.53",
		"53",
		fmt.Sprintf("%x", query),
		fmt.Sprintf("%x", reply),
	)
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	if err := s.Prepare(ctx, cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("dns server: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for dns server")
	}
}

func TestSupervisorStartRedirectsTCPConnectAfterDupRuntime(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	launcher := buildLauncherBinary(t)

	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw ingress: %v", err)
	}
	t.Cleanup(func() { _ = rawListener.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := rawListener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	restore := setLauncherCommandForTest(t, func() (string, []string, error) {
		return launcher, nil, nil
	})
	t.Cleanup(restore)

	s, err := NewSupervisor(RuntimeTargets{
		RawTCPAddr: rawListener.Addr().String(),
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			t.Fatalf("close supervisor: %v", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.Command(
		python,
		"-c",
		"import os,socket,sys; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); dup_fd=os.dup(s.fileno()); s.close(); d=socket.socket(fileno=dup_fd); d.connect((sys.argv[1], int(sys.argv[2]))); d.close()",
		"198.51.100.88",
		"9443",
	)
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	if err := s.Prepare(ctx, cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}

	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for redirected raw tcp accept after dup")
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestLauncherNoopWithoutEnv(t *testing.T) {}

func TestResolveLauncherCommandUsesSiblingLauncher(t *testing.T) {
	dir := t.TempDir()
	helperPath := filepath.Join(dir, "bbox-helper")
	launcherPath := filepath.Join(dir, "bbox-seccomp-launcher")
	if err := os.WriteFile(launcherPath, []byte("launcher"), 0o755); err != nil {
		t.Fatalf("write launcher: %v", err)
	}

	prevExecutablePath := launcherExecutablePath
	prevPathExists := launcherPathExists
	launcherExecutablePath = func() (string, error) { return helperPath, nil }
	launcherPathExists = func(path string) bool { return path == launcherPath }
	t.Cleanup(func() {
		launcherExecutablePath = prevExecutablePath
		launcherPathExists = prevPathExists
	})

	got, args, err := resolveLauncherCommand()
	if err != nil {
		t.Fatalf("resolveLauncherCommand() error = %v", err)
	}
	if got != launcherPath {
		t.Fatalf("resolveLauncherCommand() = %q, want %q", got, launcherPath)
	}
	if len(args) != 0 {
		t.Fatalf("resolveLauncherCommand() args = %#v, want nil", args)
	}
}

func setLauncherCommandForTest(t *testing.T, fn func() (string, []string, error)) func() {
	t.Helper()
	launcherCommandOverrideMu.Lock()
	prev := launcherCommandOverride
	launcherCommandOverride = fn
	launcherCommandOverrideMu.Unlock()
	return func() {
		launcherCommandOverrideMu.Lock()
		launcherCommandOverride = prev
		launcherCommandOverrideMu.Unlock()
	}
}

var (
	launcherBuildOnce sync.Once
	launcherBuildPath string
	launcherBuildErr  error
)

func buildLauncherBinary(t *testing.T) string {
	t.Helper()
	launcherBuildOnce.Do(func() {
		wd, err := os.Getwd()
		if err != nil {
			launcherBuildErr = err
			return
		}
		repoRoot := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
		buildDir, err := os.MkdirTemp("", "bbox-seccompnotify-launcher-")
		if err != nil {
			launcherBuildErr = err
			return
		}
		launcherBuildPath = filepath.Join(buildDir, "bbox-seccomp-launcher")

		cmd := exec.Command(
			"cc",
			"-O2",
			"-static",
			"-o", launcherBuildPath,
			"./cmd/bbox-seccomp-launcher/main.c",
		)
		cmd.Dir = repoRoot
		output, err := cmd.CombinedOutput()
		if err != nil {
			launcherBuildErr = fmt.Errorf("build launcher: %w: %s", err, strings.TrimSpace(string(output)))
			return
		}

		fileOutput, err := exec.Command("file", launcherBuildPath).CombinedOutput()
		if err != nil {
			launcherBuildErr = fmt.Errorf("inspect launcher binary: %w: %s", err, strings.TrimSpace(string(fileOutput)))
			return
		}
		if !strings.Contains(string(fileOutput), "statically linked") && !strings.Contains(string(fileOutput), "static-pie linked") {
			launcherBuildErr = fmt.Errorf("launcher binary is not static: %s", strings.TrimSpace(string(fileOutput)))
		}
	})
	if launcherBuildErr != nil {
		t.Fatalf("build launcher: %v", launcherBuildErr)
	}
	return launcherBuildPath
}
