/* SPDX-License-Identifier: MIT
 *
 * Copyright 2024 Marten Seemann
 * Adapted from github.com/quic-go/connect-ip-go (commit a0c35fa).
 */

package connectip

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apernet/quic-go/http3"
	"github.com/stretchr/testify/require"
)

func newRequest(target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Method = http.MethodConnect
	req.Proto = requestProtocol
	req.Header.Add("Capsule-Protocol", capsuleProtocolHeaderValue)
	return req
}

func TestNewRequest(t *testing.T) {
	req, err := NewRequest(t.Context(), "https://localhost:1234/masque/ip")
	require.NoError(t, err)
	httpReq := req.httpRequest()
	require.Equal(t, http.MethodConnect, httpReq.Method)
	require.Equal(t, requestProtocol, httpReq.Proto)
	require.Equal(t, "localhost:1234", httpReq.Host)
	require.Equal(t, "?1", req.Header().Get(http3.CapsuleProtocolHeader))

	req.Header().Set("Authorization", "Bearer token")
	require.Equal(t, "Bearer token", httpReq.Header.Get("Authorization"))
}

func TestNewRequestInvalidURL(t *testing.T) {
	for _, tc := range []struct {
		name, url, err string
	}{
		{"template with variables", "https://localhost/.well-known/masque/ip/{target}/{ipproto}/", "IP flow forwarding not supported"},
		{"template with query variables", "https://localhost/masque/ip{?target,ipproto}", "IP flow forwarding not supported"},
		{"not https", "http://localhost/masque/ip", "expected an absolute https URL"},
		{"no host", "https:///masque/ip", "expected an absolute https URL"},
		{"no path", "https://localhost", "expected an absolute https URL"},
		{"relative", "/masque/ip", "expected an absolute https URL"},
		{"unparsable", "https://local\x7fhost/", "failed to create request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewRequest(t.Context(), tc.url)
			require.ErrorContains(t, err, tc.err)
		})
	}
}

func TestProxyRequestParsing(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque/ip")
		r, err := ParseProxyRequest(req)
		require.NoError(t, err)
		require.Equal(t, &ProxyRequest{}, r)
	})

	t.Run("wrong protocol", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Proto = "not-connect-ip"
		_, err := ParseProxyRequest(req)
		require.EqualError(t, err, "unexpected protocol: not-connect-ip")
		require.Equal(t, http.StatusNotImplemented, err.(*ProxyRequestParseError).HTTPStatus)
	})

	t.Run("HTTP/2", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque/ip")
		req.Proto, req.ProtoMajor = "HTTP/2.0", 2
		req.Header.Set(":protocol", requestProtocol)
		r, err := ParseProxyRequest(req)
		require.NoError(t, err)
		require.Equal(t, &ProxyRequest{body: req.Body}, r)
	})

	t.Run("wrong protocol over HTTP/2", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Proto, req.ProtoMajor = "HTTP/2.0", 2
		req.Header.Set(":protocol", "websocket")
		_, err := ParseProxyRequest(req)
		require.EqualError(t, err, "unexpected protocol: websocket")
		require.Equal(t, http.StatusNotImplemented, err.(*ProxyRequestParseError).HTTPStatus)
	})

	t.Run("wrong request method", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Method = http.MethodHead
		_, err := ParseProxyRequest(req)
		require.EqualError(t, err, "expected CONNECT request, got HEAD")
		require.Equal(t, http.StatusMethodNotAllowed, err.(*ProxyRequestParseError).HTTPStatus)
	})

	t.Run("missing Capsule-Protocol header", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Header.Del("Capsule-Protocol")
		_, err := ParseProxyRequest(req)
		require.EqualError(t, err, "missing Capsule-Protocol header")
		require.Equal(t, http.StatusBadRequest, err.(*ProxyRequestParseError).HTTPStatus)
	})

	for _, tc := range []struct {
		name   string
		values []string
		valid  bool
	}{
		{name: "true", values: []string{"?1"}, valid: true},
		{name: "surrounding spaces", values: []string{" ?1 "}, valid: true},
		{name: "parameters", values: []string{"?1;a;b=?0;c=\"x\""}, valid: true},
		{name: "false", values: []string{"?0"}},
		{name: "integer", values: []string{"1"}},
		{name: "empty", values: []string{""}},
		{name: "not a structured field", values: []string{"🤡"}},
		{name: "longer token", values: []string{"?10"}},
		{name: "space before parameters", values: []string{"?1 ;a"}},
		{name: "list", values: []string{"?1, ?1"}},
		{name: "multiple field lines", values: []string{"?1", "?1"}},
	} {
		t.Run("Capsule-Protocol header: "+tc.name, func(t *testing.T) {
			req := newRequest("https://localhost:1234/masque")
			req.Header[http3.CapsuleProtocolHeader] = tc.values
			_, err := ParseProxyRequest(req)
			if tc.valid {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, "invalid capsule header value")
			require.Equal(t, http.StatusBadRequest, err.(*ProxyRequestParseError).HTTPStatus)
		})
	}
}
