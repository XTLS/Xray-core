/* SPDX-License-Identifier: MIT
 *
 * Copyright 2024 Marten Seemann
 * Adapted from github.com/quic-go/connect-ip-go (commit a0c35fa).
 */

package connectip

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/apernet/quic-go/http3"
)

const requestProtocol = "connect-ip"

const capsuleProtocolHeaderValue = "?1"

type Request struct {
	req *http.Request
}

func NewRequest(ctx context.Context, rawURL string) (*Request, error) {
	if strings.ContainsAny(rawURL, "{}") {
		return nil, errors.New("connect-ip: IP flow forwarding not supported: URL contains a URI Template expression")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("connect-ip: failed to create request: %w", err)
	}
	if req.URL.Scheme != "https" || req.URL.Host == "" || !strings.HasPrefix(req.URL.Path, "/") {
		return nil, fmt.Errorf("connect-ip: invalid proxy URL %q: expected an absolute https URL with a host and a path", rawURL)
	}
	req.Proto = requestProtocol
	req.Host = req.URL.Host
	req.Header.Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	return &Request{req: req}, nil
}

func (r *Request) Header() http.Header { return r.req.Header }

func (r *Request) httpRequest() *http.Request { return r.req }

type ProxyRequest struct{}

type ProxyRequestParseError struct {
	HTTPStatus int
	Err        error
}

func (e *ProxyRequestParseError) Error() string { return e.Err.Error() }
func (e *ProxyRequestParseError) Unwrap() error { return e.Err }

func ParseProxyRequest(r *http.Request) (*ProxyRequest, error) {
	if r.Method != http.MethodConnect {
		return nil, &ProxyRequestParseError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("expected CONNECT request, got %s", r.Method),
		}
	}
	if r.Proto != requestProtocol {
		return nil, &ProxyRequestParseError{
			HTTPStatus: http.StatusNotImplemented,
			Err:        fmt.Errorf("unexpected protocol: %s", r.Proto),
		}
	}
	capsuleHeaderValues, ok := r.Header[http3.CapsuleProtocolHeader]
	if !ok {
		return nil, &ProxyRequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("missing Capsule-Protocol header"),
		}
	}
	if !isCapsuleProtocolEnabled(capsuleHeaderValues) {
		return nil, &ProxyRequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("invalid capsule header value: %s", capsuleHeaderValues),
		}
	}

	return &ProxyRequest{}, nil
}

func isCapsuleProtocolEnabled(values []string) bool {
	v := strings.Trim(strings.Join(values, ","), " ")
	return v == capsuleProtocolHeaderValue || strings.HasPrefix(v, capsuleProtocolHeaderValue+";")
}
