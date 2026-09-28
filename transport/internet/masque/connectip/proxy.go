/* SPDX-License-Identifier: MIT
 *
 * Copyright 2024 Marten Seemann
 * Adapted from github.com/quic-go/connect-ip-go (commit a0c35fa).
 */

package connectip

import (
	"bufio"
	"errors"
	"net/http"

	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
)

var contextIDZero = quicvarint.Append([]byte{}, 0)

type Proxy struct{}

func (s *Proxy) Proxy(w http.ResponseWriter, r *ProxyRequest) (*Conn, error) {
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok && (r == nil || r.body == nil) {
		return nil, errors.New("connect-ip: response writer is neither an HTTP/3 nor an HTTP/2 stream")
	}
	w.Header().Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	w.WriteHeader(http.StatusOK)

	if ok {
		return newProxiedConn(streamer.HTTPStream()), nil
	}
	controller := http.NewResponseController(w)
	if err := controller.Flush(); err != nil {
		return nil, err
	}
	return newProxiedConn(&http2ResponseStream{
		reader:     bufio.NewReader(r.body),
		body:       r.body,
		w:          w,
		controller: controller,
	}), nil
}
