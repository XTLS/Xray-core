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

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
)

const (
	cloudflareProtocol = "cf-connect-ip"

	SettingDatagramDraft00 uint64 = 0x276
)

type ClientConn struct {
	clientConn *http3.ClientConn
	quicConn   *quic.Conn
}

func NewClientConn(conn *http3.ClientConn) *ClientConn {
	return &ClientConn{clientConn: conn}
}

func NewCloudflareClientConn(conn *http3.ClientConn, quicConn *quic.Conn) *ClientConn {
	return &ClientConn{clientConn: conn, quicConn: quicConn}
}

func (c *ClientConn) Dial(req *Request) (*Conn, *http.Response, error) {
	httpReq := req.httpRequest()
	if httpReq.URL == nil {
		return nil, nil, errors.New("connect-ip: request URL is nil")
	}
	if httpReq.Host == "" && httpReq.URL.Host == "" {
		return nil, nil, errors.New("connect-ip: request needs a host")
	}
	cloudflare := c.quicConn != nil
	if cloudflare {
		httpReq = httpReq.Clone(httpReq.Context())
		httpReq.Proto = cloudflareProtocol
	}

	select {
	case <-httpReq.Context().Done():
		return nil, nil, context.Cause(httpReq.Context())
	case <-c.clientConn.Context().Done():
		return nil, nil, context.Cause(c.clientConn.Context())
	case <-c.clientConn.ReceivedSettings():
	}

	settings := c.clientConn.Settings()
	if !settings.EnableExtendedConnect && !cloudflare {
		return nil, nil, errors.New("connect-ip: server didn't enable Extended CONNECT")
	}
	draftDatagrams := cloudflare && !settings.EnableDatagrams && settings.Other[SettingDatagramDraft00] == 1
	if !settings.EnableDatagrams && !draftDatagrams {
		return nil, nil, errors.New("connect-ip: server didn't enable datagrams")
	}

	rstr, err := c.clientConn.OpenRequestStream(httpReq.Context())
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to open request stream: %w", err)
	}
	var keepStream bool
	defer func() {
		if !keepStream {
			rstr.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
			rstr.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
		}
	}()
	if err := rstr.SendRequestHeader(httpReq); err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to send request: %w", err)
	}
	rsp, err := rstr.ReadResponse()
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to read response: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		return nil, rsp, fmt.Errorf("connect-ip: server responded with %d", rsp.StatusCode)
	}
	keepStream = true
	if draftDatagrams {
		return newProxiedConn(&draftDatagramStream{RequestStream: rstr, conn: c.quicConn}), rsp, nil
	}
	return newProxiedConn(rstr), rsp, nil
}

type draftDatagramStream struct {
	*http3.RequestStream
	conn *quic.Conn
}

func (s *draftDatagramStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	for {
		b, err := s.conn.ReceiveDatagram(ctx)
		if err != nil {
			return nil, err
		}
		quarterStreamID, n, err := quicvarint.Parse(b)
		if err != nil || quic.StreamID(quarterStreamID*4) != s.StreamID() {
			continue
		}
		return b[n:], nil
	}
}
