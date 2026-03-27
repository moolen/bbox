package bbox

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
)

func proxyURL() string {
	return "http://localhost:31111"
}

type roundTripper interface {
	RoundTrip(*http.Request) (*http.Response, error)
}

type forwardedRequest struct {
	Method string
	URL    string
	Header http.Header
	Body   []byte
}

type forwardedResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	Error      string
}

type bridgeRoundTripper struct {
	mu  sync.Mutex
	enc *gob.Encoder
	dec *gob.Decoder
}

func newBridgeRoundTripper(conn net.Conn) *bridgeRoundTripper {
	return &bridgeRoundTripper{
		enc: gob.NewEncoder(conn),
		dec: gob.NewDecoder(conn),
	}
}

func rewriteProxyRequest(req *http.Request) (*http.Request, error) {
	if req.Method == http.MethodConnect {
		return nil, errors.New("CONNECT is not implemented in this proof of concept")
	}
	if req.URL == nil || req.URL.Scheme == "" || req.URL.Host == "" {
		return nil, errors.New("proxy request must use an absolute URL")
	}

	out := req.Clone(req.Context())
	urlCopy := *req.URL
	out.URL = &urlCopy
	out.RequestURI = ""
	out.Host = out.URL.Host
	out.Header = req.Header.Clone()
	out.Header.Del("Proxy-Connection")

	return out, nil
}

func newProxyHandler(rt roundTripper) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		log.Printf("proxy request: %s %s", req.Method, req.URL.String())

		outReq, err := rewriteProxyRequest(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp, err := rt.RoundTrip(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, resp.Body); err != nil {
			log.Printf("copy response body: %v", err)
		}
	})
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func (b *bridgeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	payload := forwardedRequest{
		Method: req.Method,
		URL:    req.URL.String(),
		Header: req.Header.Clone(),
		Body:   body,
	}
	if err := b.enc.Encode(&payload); err != nil {
		return nil, err
	}

	var forwarded forwardedResponse
	if err := b.dec.Decode(&forwarded); err != nil {
		return nil, err
	}

	return &http.Response{
		Status:        fmt.Sprintf("%d %s", forwarded.StatusCode, http.StatusText(forwarded.StatusCode)),
		StatusCode:    forwarded.StatusCode,
		Header:        forwarded.Header,
		Body:          io.NopCloser(bytes.NewReader(forwarded.Body)),
		ContentLength: int64(len(forwarded.Body)),
		Request:       req,
	}, nil
}
