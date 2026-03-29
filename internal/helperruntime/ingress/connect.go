package ingress

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const connectHandshakeTimeout = 5 * time.Second

var timeNow = time.Now

func HandleConnect(rt Bridge, w http.ResponseWriter, req *http.Request) {
	host, port, err := parseConnectTarget(req.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "proxy does not support connection hijacking", http.StatusInternalServerError)
		return
	}

	conn, rw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("hijack proxy connection: %v", err), http.StatusBadGateway)
		return
	}

	bufferedPayload, err := drainHijackBufferedBytes(rw)
	if err != nil {
		writeConnectError(rt, conn, http.StatusBadGateway, fmt.Sprintf("read buffered connect payload: %v", err))
		return
	}

	_ = conn.SetDeadline(timeNow().Add(connectHandshakeTimeout))
	connectCtx, cancelConnect := context.WithTimeout(req.Context(), connectHandshakeTimeout)
	defer cancelConnect()

	id, tunnelCh, response, err := rt.Connect(connectCtx, host, port)
	if err != nil {
		_ = conn.SetDeadline(time.Time{})
		rt.UnregisterTunnel(id)
		writeConnectError(rt, conn, connectErrorStatus(err), err.Error())
		return
	}

	statusCode := response.StatusCode
	if statusCode == 0 {
		statusCode = http.StatusBadGateway
	}
	if response.Error != "" || statusCode < 200 || statusCode >= 300 {
		message := response.Message
		if message == "" {
			message = response.Error
		}
		rt.UnregisterTunnel(id)
		writeConnectError(rt, conn, statusCode, message)
		return
	}

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		if sendErr := rt.SendTunnelClose(id, false, err); sendErr != nil {
			bridgeLogger(rt).Printf("send tunnel close: %v", sendErr)
		}
		rt.UnregisterTunnel(id)
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})

	tunnelCtx, cancelTunnel := context.WithCancel(req.Context())

	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			cancelTunnel()
			_ = conn.Close()
		})
	}
	cleanup := func(result TunnelRelayResult) {
		if result.SendClose {
			if err := rt.SendTunnelClose(id, result.Write, result.Err); err != nil {
				bridgeLogger(rt).Printf("send tunnel close: %v", err)
			}
		}
		if !result.Terminal {
			return
		}
		shutdown()
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		cleanup(rt.RelayPayloadToTunnel(conn, id, bufferedPayload))
	}()

	go func() {
		defer wg.Done()
		cleanup(rt.RelayTunnelToPayload(tunnelCtx, conn, tunnelCh))
	}()

	wg.Wait()
	shutdown()
	rt.UnregisterTunnel(id)
}

func drainHijackBufferedBytes(rw *bufio.ReadWriter) ([]byte, error) {
	if rw == nil || rw.Reader == nil {
		return nil, nil
	}
	n := rw.Reader.Buffered()
	if n == 0 {
		return nil, nil
	}

	buf := make([]byte, n)
	if _, err := io.ReadFull(rw.Reader, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeConnectError(rt Bridge, conn net.Conn, statusCode int, message string) {
	if statusCode < 400 || statusCode > 599 {
		statusCode = http.StatusBadGateway
	}
	message = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(message, "\r", " "), "\n", " "))
	if message == "" {
		message = http.StatusText(statusCode)
	}
	statusText := http.StatusText(statusCode)
	if statusText == "" {
		statusText = "Error"
	}
	body := message + "\n"
	if _, err := io.WriteString(conn, fmt.Sprintf("HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\n\r\n%s", statusCode, statusText, len(body), body)); err != nil {
		bridgeLogger(rt).Printf("write connect error response: %v", err)
	}
	_ = conn.Close()
}

func connectErrorStatus(err error) int {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout
	default:
		return http.StatusBadGateway
	}
}

func parseConnectTarget(target string) (string, int, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", 0, errors.New("malformed CONNECT target: host is required")
	}

	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, fmt.Errorf("malformed CONNECT target %q", target)
	}
	if host == "" {
		return "", 0, errors.New("malformed CONNECT target: host is required")
	}

	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("malformed CONNECT target %q", target)
	}

	return host, port, nil
}
