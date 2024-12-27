package httpupgrade

import (
	"bufio"
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	"github.com/GFW-knocker/Xray-core/transport/internet/stat"
	"github.com/GFW-knocker/Xray-core/transport/internet/tls"
)

type ConnRF struct {
	net.Conn
	Req   *http.Request
	First bool
}

func (c *ConnRF) Read(b []byte) (int, error) {
	if c.First {
		c.First = false
		// create reader capped to size of `b`, so it can be fully drained into
		// `b` later with a single Read call
		reader := bufio.NewReaderSize(c.Conn, len(b))
		resp, err := http.ReadResponse(reader, c.Req) // nolint:bodyclose
		if err != nil {
			return 0, err
		}
		if resp.Status != "101 Switching Protocols" ||
			strings.ToLower(resp.Header.Get("Upgrade")) != "websocket" ||
			strings.ToLower(resp.Header.Get("Connection")) != "upgrade" {
			return 0, errors.New("unrecognized reply")
		}
		// drain remaining bufreader
		return reader.Read(b[:reader.Buffered()])
	}
	return c.Conn.Read(b)
}

func dialhttpUpgrade(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (net.Conn, error) {
	transportConfiguration := streamSettings.ProtocolSettings.(*Config)

	pconn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
	if err != nil {
		errors.LogErrorInner(ctx, err, "failed to dial to ", dest)
		return nil, err
	}

	var conn net.Conn
	var requestURL url.URL
	tConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tConfig != nil {
		tlsConfig := tConfig.GetTLSConfig(tls.WithDestination(dest), tls.WithNextProto("http/1.1"))
		if fingerprint := tls.GetFingerprint(tConfig.Fingerprint); fingerprint != nil {
			conn = tls.UClient(pconn, tlsConfig, fingerprint)
			if err := conn.(*tls.UConn).WebsocketHandshakeContext(ctx); err != nil {
				return nil, err
			}
		} else {
			conn = tls.Client(pconn, tlsConfig)
		}
		requestURL.Scheme = "https"
	} else {
		conn = pconn
		requestURL.Scheme = "http"
	}

	requestURL.Host = transportConfiguration.Host
	if requestURL.Host == "" && tConfig != nil {
		requestURL.Host = tConfig.ServerName
	}
	if requestURL.Host == "" {
		requestURL.Host = dest.Address.String()
	}
	requestURL.Path = transportConfiguration.GetNormalizedPath()
	req := &http.Request{
		Method: http.MethodGet,
		URL:    &requestURL,
		Header: make(http.Header),
	}
	for key, value := range transportConfiguration.Header {
		AddHeader(req.Header, key, value)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	// GFW-Knocker
	uagent := req.Header.Get("User-Agent")
	if uagent == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	}

	err = req.Write(conn)
	if err != nil {
		return nil, err
	}

	connRF := &ConnRF{
		Conn:  conn,
		Req:   req,
		First: true,
	}

	if transportConfiguration.Ed == 0 {
		_, err = connRF.Read([]byte{})
		if err != nil {
			return nil, err
		}
	}

	return connRF, nil
}

// http.Header.Add() will convert headers to MIME header format.
// Some people don't like this because they want to send "Web*S*ocket".
// So we add a simple function to replace that method.
func AddHeader(header http.Header, key, value string) {
	header[key] = append(header[key], value)
}

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	errors.LogInfo(ctx, "creating connection to ", dest)

	conn, err := dialhttpUpgrade(ctx, dest, streamSettings)
	if err != nil {
		return nil, errors.New("failed to dial request to ", dest).Base(err)
	}
	return stat.Connection(conn), nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
