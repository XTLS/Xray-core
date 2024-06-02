package splithttp

import (
	"context"
	gotls "crypto/tls"
	"io"
	gonet "net"
	"net/http"
	"net/http/httptrace"
	"net/url"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"
	"golang.org/x/net/http2"
)

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

type utlsRoundtripper struct {
	dialTLSContext func(ctx context.Context)
	h2Transport    http2.Transport
	h1Transport    http.Transport
}

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	newError("dialing splithttp to ", dest).WriteToLog(session.ExportIDToError(ctx))

	var requestURL url.URL
	var gotlsConfig *gotls.Config

	transportConfiguration := streamSettings.ProtocolSettings.(*Config)
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)

	if tlsConfig != nil {
		gotlsConfig = tlsConfig.GetTLSConfig(tls.WithDestination(dest))
		requestURL.Scheme = "https"
	} else {
		requestURL.Scheme = "http"
	}
	requestURL.Host = transportConfiguration.Host
	if requestURL.Host == "" {
		requestURL.Host = dest.NetAddr()
	}
	requestURL.Path = transportConfiguration.GetNormalizedPath()

	dialContext := func(ctxInner context.Context) (net.Conn, error) {
		conn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
		if err != nil {
			return nil, err
		}

		if gotlsConfig != nil {
			if fingerprint := tls.GetFingerprint(tlsConfig.Fingerprint); fingerprint != nil {
				conn = tls.UClient(conn, gotlsConfig, fingerprint)
				if err := conn.(*tls.UConn).HandshakeContext(ctx); err != nil {
					return nil, err
				}
			} else {
				conn = tls.Client(conn, gotlsConfig)
			}
		}

		return conn, nil
	}

	var httpTransport http.RoundTripper

	if tlsConfig != nil {
		httpTransport = &http2.Transport{
			DialTLSContext: func(ctxInner context.Context, network string, addr string, cfg *gotls.Config) (net.Conn, error) {
				return dialContext(ctxInner)
			},
		}
	} else {
		httpDialContext := func(ctxInner context.Context, network string, addr string) (net.Conn, error) {
			return dialContext(ctxInner)
		}
		httpTransport = &http.Transport{
			DialTLSContext: httpDialContext,
			DialContext:    httpDialContext,
		}
	}

	httpClient := http.Client{
		Transport: httpTransport,
	}

	var remoteAddr gonet.Addr
	var localAddr gonet.Addr

	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			remoteAddr = connInfo.Conn.RemoteAddr()
			localAddr = connInfo.Conn.LocalAddr()
		},
	}

	sessionIdUuid := uuid.New()
	sessionId := sessionIdUuid.String()

	req, err := http.NewRequestWithContext(
		httptrace.WithClientTrace(ctx, trace),
		"GET",
		requestURL.String()+"?session="+sessionId,
		nil,
	)
	if err != nil {
		return nil, err
	}

	req.Header = transportConfiguration.GetRequestHeader()

	downResponse, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if downResponse.StatusCode != 200 {
		return nil, newError("invalid status code on download:", downResponse.Status)
	}

	uploadUrl := requestURL.String() + "?session=" + sessionId

	uploadPipeReader, uploadPipeWriter := pipe.New(pipe.WithSizeLimit(1000000))

	go func() {
		// by offloading the uploads into a buffered pipe, multiple conn.Write
		// calls get automatically batched together into larger POST requests.
		// without batching, bandwidth is extremely limited.
		for {
			chunk, err := uploadPipeReader.ReadMultiBuffer()
			if err != nil {
				break
			}

			req, err := http.NewRequest("POST", uploadUrl, &buf.MultiBufferContainer{MultiBuffer: chunk})
			if err != nil {
				break
			}

			req.Header = transportConfiguration.GetRequestHeader()

			resp, err := httpClient.Do(req)
			if err != nil {
				break
			}

			if resp.StatusCode != 200 {
				break
			}
		}
	}()

	// skip "ok" response
	trashHeader := []byte{0, 0}
	_, err = io.ReadFull(downResponse.Body, trashHeader)
	if err != nil {
		return nil, newError("failed to read initial response")
	}

	conn := splitConn{
		downloadPipe: &uploadWriter{
			uploadPipe: buf.NewBufferedWriter(uploadPipeWriter),
		},
		uploadPipe: downResponse.Body,
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
	}

	return stat.Connection(&conn), nil
}

type uploadWriter struct {
	uploadPipe *buf.BufferedWriter
}

func (c *uploadWriter) Write(b []byte) (int, error) {
	bytes, err := c.uploadPipe.Write(b)
	if err == nil {
		c.uploadPipe.Flush()
	}
	return bytes, err
}

func (c *uploadWriter) Close() error {
	return c.uploadPipe.Close()
}
