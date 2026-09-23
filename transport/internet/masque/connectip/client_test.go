/* SPDX-License-Identifier: MIT
 *
 * Copyright 2024 Marten Seemann
 * Adapted from github.com/quic-go/connect-ip-go (commit a0c35fa).
 */

package connectip

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientWaitForSettings(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	ln, err := quic.Listen(conn, tlsConf, &quic.Config{EnableDatagrams: true})
	require.NoError(t, err)
	defer ln.Close()

	h3conn := dialHTTP3(t, conn.LocalAddr().String())
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	req, err := NewRequest(ctx, "https://example.org/.well-known/masque/ip/")
	require.NoError(t, err)
	_, _, err = NewClientConn(h3conn).Dial(req)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestClientDatagramCheck(t *testing.T) {
	s := http3.Server{
		TLSConfig:       tlsConf,
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		EnableDatagrams: false,
	}
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	go func() { s.Serve(ln) }()
	defer s.Close()

	h3conn := dialHTTP3(t, ln.LocalAddr().String())
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, err := NewRequest(ctx, "https://example.org/.well-known/masque/ip/")
	require.NoError(t, err)
	_, _, err = NewClientConn(h3conn).Dial(req)
	require.ErrorContains(t, err, "connect-ip: server didn't enable datagrams")
}

func TestNewClientConnSharesHTTP3Connection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer ln.Close()
	url := "https://" + ln.LocalAddr().String()

	mux := http.NewServeMux()
	mux.HandleFunc("/connect-ip", func(w http.ResponseWriter, r *http.Request) {
		req, err := ParseProxyRequest(r)
		if !assert.NoError(t, err) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, err = (&Proxy{}).Proxy(w, req)
		assert.NoError(t, err)
	})
	mux.HandleFunc("GET /hello", func(http.ResponseWriter, *http.Request) {})
	s := http3.Server{Handler: mux, TLSConfig: tlsConf, EnableDatagrams: true}
	go func() { s.Serve(ln) }()
	defer s.Close()

	h3conn := dialHTTP3(t, ln.LocalAddr().String())
	httpClient := &http.Client{Transport: h3conn, Timeout: time.Second}
	checkHTTP := func() {
		t.Helper()
		rsp, err := httpClient.Get(url + "/hello")
		require.NoError(t, err)
		rsp.Body.Close()
		require.Equal(t, http.StatusOK, rsp.StatusCode)
	}

	checkHTTP()
	req, err := NewRequest(ctx, url+"/connect-ip")
	require.NoError(t, err)
	tunnel, rsp, err := NewClientConn(h3conn).Dial(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rsp.StatusCode)
	checkHTTP()
	require.NoError(t, tunnel.Close())
	checkHTTP()
}
