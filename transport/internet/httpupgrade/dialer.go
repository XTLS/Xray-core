package httpupgrade

import (
	"bufio"
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type ConnRF struct {
	net.Conn
	First bool
}

func (c *ConnRF) Read(b []byte) (int, error) {
	if c.First {
		c.First = false
		// TODO The bufio usage here is unreliable
		resp, err := http.ReadResponse(bufio.NewReader(c.Conn), nil) // nolint:bodyclose
		if err != nil {
			return 0, err
		}
		if resp.Status != "101 Switching Protocols" ||
			strings.ToLower(resp.Header.Get("Upgrade")) != "websocket" ||
			strings.ToLower(resp.Header.Get("Connection")) != "upgrade" {
			return 0, newError("unrecognized reply")
		}
	}
	return c.Conn.Read(b)
}

func dialhttpUpgrade(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (net.Conn, error) {
	transportConfiguration := streamSettings.ProtocolSettings.(*Config)

	pconn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
	if err != nil {
		newError("failed to dial to ", dest).Base(err).AtError().WriteToLog()
		return nil, err
	}

	var conn net.Conn
	var requestURL url.URL
	if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
		tlsConfig := config.GetTLSConfig(tls.WithDestination(dest), tls.WithNextProto("http/1.1"))
		if fingerprint := tls.GetFingerprint(config.Fingerprint); fingerprint != nil {
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

	requestURL.Host = dest.NetAddr()
	requestURL.Path = transportConfiguration.GetNormalizedPath()

	var headersBuilder strings.Builder

	headersBuilder.WriteString("GET ")
	headersBuilder.WriteString(requestURL.String())
	headersBuilder.WriteString(" HTTP/1.1\r\n")
	hasConnectionHeader := false
	hasUpgradeHeader := false
	for key, value := range transportConfiguration.Header {
		if strings.ToLower(key) == "connection" {
			hasConnectionHeader = true
		}
		if strings.ToLower(key) == "upgrade" {
			hasUpgradeHeader = true
		}
		headersBuilder.WriteString(key)
		headersBuilder.WriteString(": ")
		headersBuilder.WriteString(value)
		headersBuilder.WriteString("\r\n")
	}

	if !hasConnectionHeader {
		headersBuilder.WriteString("Connection: upgrade\r\n")
	}

	if !hasUpgradeHeader {
		headersBuilder.WriteString("Upgrade: WebSocket\r\n")
	}

	headersBuilder.WriteString("\r\n")
	_, err = conn.Write([]byte(headersBuilder.String()))
	if err != nil {
		return nil, err
	}

	connRF := &ConnRF{
		Conn:  conn,
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

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	newError("creating connection to ", dest).WriteToLog(session.ExportIDToError(ctx))

	conn, err := dialhttpUpgrade(ctx, dest, streamSettings)
	if err != nil {
		return nil, newError("failed to dial request to ", dest).Base(err)
	}
	return stat.Connection(conn), nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
