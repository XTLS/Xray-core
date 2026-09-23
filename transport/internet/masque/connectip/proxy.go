/* SPDX-License-Identifier: MIT
 *
 * Copyright 2024 Marten Seemann
 * Adapted from github.com/quic-go/connect-ip-go (commit a0c35fa).
 */

package connectip

import (
	"errors"
	"net/http"

	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
)

var contextIDZero = quicvarint.Append([]byte{}, 0)

type Proxy struct{}

func (s *Proxy) Proxy(w http.ResponseWriter, _ *ProxyRequest) (*Conn, error) {
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		return nil, errors.New("connect-ip: response writer is not an HTTP/3 stream")
	}
	w.Header().Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	w.WriteHeader(http.StatusOK)

	return newProxiedConn(streamer.HTTPStream()), nil
}
