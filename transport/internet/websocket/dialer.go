package websocket

import (
	"bytes"
	"context"
	ltls "crypto/tls"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	gonet "net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

//go:embed dialer.html
var webpage []byte

var conns chan *websocket.Conn

const RANDOM_CUT = 1
const SNI = 2

func GetFragmentationIdByName(name string) int {
	switch strings.ToLower(name) {
	case "random":
		return RANDOM_CUT
	case "sni":
		return SNI
	default:
		return RANDOM_CUT
	}
}

type FragmentedClientHelloConn struct {
	net.Conn
	clientHelloCount             int
	maxFragmentSize              int
	sni                          string
	mode                         int
	intervalTimeoutBetweenChunks int64
}

func (c *FragmentedClientHelloConn) Write(b []byte) (n int, err error) {
	if len(b) >= 5 && b[0] == 22 && c.clientHelloCount < 2 {
		n, err = sendFragmentedClientHello(c.Conn, b, c.sni, c.maxFragmentSize, c.intervalTimeoutBetweenChunks, c.mode)
		if err == nil {
			c.clientHelloCount++
			return n, err
		}
	}

	return c.Conn.Write(b)
}

func sendFragmentedClientHello(conn net.Conn, clientHello []byte, sni string, maxFragmentSize int, intervalTimeoutBetweenChunks int64, mode int) (n int, err error) {
	if len(clientHello) < 5 || clientHello[0] != 22 {
		return 0, errors.New("not a valid TLS ClientHello message")
	}

	clientHelloLen := (int(clientHello[3]) << 8) | int(clientHello[4])

	switch mode {
	case RANDOM_CUT:
		sendFragmentedClientHelloByRandomCuts(conn, clientHello, clientHelloLen, maxFragmentSize, intervalTimeoutBetweenChunks)
		if err != nil {
			return 0, err
		}
	case SNI:
		sendFragmentedClientHelloBySni(conn, clientHello, clientHelloLen, maxFragmentSize, sni, intervalTimeoutBetweenChunks)
		if err != nil {
			return 0, err
		}
	}

	return len(clientHello), nil
}

func sendFragmentedClientHelloByRandomCuts(conn net.Conn, clientHello []byte, clientHelloLen int, maxFragmentSize int, intervalTimeoutBetweenChunks int64) (n int, err error) {
	clientHelloData := clientHello[5:]
	for i := 0; i < clientHelloLen; i += maxFragmentSize {
		fragmentEnd := i + maxFragmentSize
		if fragmentEnd > clientHelloLen {
			fragmentEnd = clientHelloLen
		}

		fragment := clientHelloData[i:fragmentEnd]
		if intervalTimeoutBetweenChunks != 0 {
			time.Sleep(time.Duration(intervalTimeoutBetweenChunks) * time.Millisecond)
		}
		err = writeFragmentedRecord(conn, 22, fragment)
		if err != nil {
			return 0, err
		}
	}
	return 1, nil
}

func sendFragmentedClientHelloBySni(conn net.Conn, clientHello []byte, clientHelloLen int, maxFragmentSize int, sni string, intervalTimeoutBetweenChunks int64) (n int, err error) {
	sniIndex := bytes.Index(clientHello, []byte(sni))

	sniFound := false
	if sniIndex != -1 {
		sniFound = true
	}

	if sniFound {
		clientHelloData := clientHello[5:]
		originalMaxFragmentSize := maxFragmentSize
		sniIndexInClientHelloData := sniIndex - 5

		for i := 0; i < clientHelloLen; i = i + maxFragmentSize {
			if i == sniIndexInClientHelloData {
				maxFragmentSize = 1
			}
			if i < sniIndexInClientHelloData {
				maxFragmentSize = sniIndexInClientHelloData
			}
			if i == sniIndexInClientHelloData+len(sni) {
				maxFragmentSize = originalMaxFragmentSize
			}

			fragmentEnd := i + maxFragmentSize
			if fragmentEnd > clientHelloLen {
				fragmentEnd = clientHelloLen
			}

			fragment := clientHelloData[i:fragmentEnd]

			if intervalTimeoutBetweenChunks != 0 {
				time.Sleep(time.Duration(intervalTimeoutBetweenChunks) * time.Millisecond)
			}

			err = writeFragmentedRecord(conn, 22, fragment)
			if err != nil {
				return 0, err
			}
		}
	} else {
		sendFragmentedClientHelloByRandomCuts(conn, clientHello, clientHelloLen, maxFragmentSize, intervalTimeoutBetweenChunks)
		if err != nil {
			return 0, err
		}
	}

	return 1, nil
}

func writeFragmentedRecord(conn net.Conn, contentType uint8, data []byte) error {
	header := make([]byte, 5)
	header[0] = byte(contentType)
	binary.BigEndian.PutUint16(header[1:], uint16(ltls.VersionTLS12))
	binary.BigEndian.PutUint16(header[3:], uint16(len(data)))

	_, err := conn.Write(append(header, data...))
	return err
}

func wrapWithFragmentation(conn net.Conn, sniPart string, maxFragmentSize int, intervalTimeoutBetweenChunks int64, mode int) net.Conn {
	if maxFragmentSize > 0 {
		return &FragmentedClientHelloConn{
			Conn:                         conn,
			maxFragmentSize:              int(maxFragmentSize),
			sni:                          sniPart,
			intervalTimeoutBetweenChunks: intervalTimeoutBetweenChunks,
			mode:                         mode,
		}
	}
	return conn
}

func init() {
	if addr := os.Getenv("XRAY_BROWSER_DIALER"); addr != "" {
		conns = make(chan *websocket.Conn, 256)
		go http.ListenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/websocket" {
				if conn, err := upgrader.Upgrade(w, r, nil); err == nil {
					conns <- conn
				} else {
					fmt.Println("unexpected error")
				}
			} else {
				w.Write(webpage)
			}
		}))
	}
}

// Dial dials a WebSocket connection to the given destination.
func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	newError("creating connection to ", dest).WriteToLog(session.ExportIDToError(ctx))
	var conn net.Conn
	if streamSettings.ProtocolSettings.(*Config).Ed > 0 {
		ctx, cancel := context.WithCancel(ctx)
		conn = &delayDialConn{
			dialed:         make(chan bool, 1),
			cancel:         cancel,
			ctx:            ctx,
			dest:           dest,
			streamSettings: streamSettings,
		}
	} else {
		var err error
		if conn, err = dialWebSocket(ctx, dest, streamSettings, nil); err != nil {
			return nil, newError("failed to dial WebSocket").Base(err)
		}
	}
	return stat.Connection(conn), nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

func dialWebSocket(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig, ed []byte) (net.Conn, error) {
	wsSettings := streamSettings.ProtocolSettings.(*Config)

	dialer := &websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			return internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
		},
		ReadBufferSize:   4 * 1024,
		WriteBufferSize:  4 * 1024,
		HandshakeTimeout: time.Second * 8,
	}

	protocol := "ws"

	if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
		protocol = "wss"
		tlsConfig := config.GetTLSConfig(tls.WithDestination(dest), tls.WithNextProto("http/1.1"))
		dialer.TLSClientConfig = tlsConfig
		if fingerprint := tls.GetFingerprint(config.Fingerprint); fingerprint != nil {
			dialer.NetDialTLSContext = func(_ context.Context, _, addr string) (gonet.Conn, error) {
				// Like the NetDial in the dialer
				pconn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
				if err != nil {
					newError("failed to dial to " + addr).Base(err).AtError().WriteToLog()
					return nil, err
				}

				if wsSettings.Fragmentation != nil && wsSettings.Fragmentation.Enabled {
					// Wrap the connection with fragmentation logic
					address := dest.Address.String()
					if address == "" {
						address = wsSettings.Fragmentation.Sni
					}
					maxFragmentSize := rand.Intn(int(wsSettings.Fragmentation.MaxChunkSize))
					pconn = wrapWithFragmentation(pconn, address, maxFragmentSize, wsSettings.Fragmentation.FragmentionIntervalTimeout, GetFragmentationIdByName(wsSettings.Fragmentation.Strategy))
				}

				// TLS and apply the handshake
				cn := tls.UClient(pconn, tlsConfig, fingerprint).(*tls.UConn)
				if err := cn.WebsocketHandshake(); err != nil {
					newError("failed to dial to " + addr).Base(err).AtError().WriteToLog()
					return nil, err
				}
				if !tlsConfig.InsecureSkipVerify {
					if err := cn.VerifyHostname(tlsConfig.ServerName); err != nil {
						newError("failed to dial to " + addr).Base(err).AtError().WriteToLog()
						return nil, err
					}
				}
				return cn, nil
			}
		} else {
			if wsSettings.Fragmentation != nil && wsSettings.Fragmentation.Enabled {
				originalDialerNetDial := dialer.NetDial
				dialer.NetDial = func(network, addr string) (net.Conn, error) {
					conn, err := originalDialerNetDial(network, addr)
					if err != nil {
						return nil, err
					}

					address := dest.Address.String()
					if address == "" {
						address = wsSettings.Fragmentation.Sni
					}

					maxFragmentSize := rand.Intn(int(wsSettings.Fragmentation.MaxChunkSize))
					conn = wrapWithFragmentation(conn, address, maxFragmentSize, wsSettings.Fragmentation.FragmentionIntervalTimeout, GetFragmentationIdByName(wsSettings.Fragmentation.Strategy))

					return conn, nil
				}
			}
		}
	}

	host := dest.NetAddr()
	if (protocol == "ws" && dest.Port == 80) || (protocol == "wss" && dest.Port == 443) {
		host = dest.Address.String()
	}
	uri := protocol + "://" + host + wsSettings.GetNormalizedPath()

	if conns != nil {
		data := []byte(uri)
		if ed != nil {
			data = append(data, " "+base64.RawURLEncoding.EncodeToString(ed)...)
		}
		var conn *websocket.Conn
		for {
			conn = <-conns
			if conn.WriteMessage(websocket.TextMessage, data) != nil {
				conn.Close()
			} else {
				break
			}
		}
		if _, p, err := conn.ReadMessage(); err != nil {
			conn.Close()
			return nil, err
		} else if s := string(p); s != "ok" {
			conn.Close()
			return nil, newError(s)
		}
		return newConnection(conn, conn.RemoteAddr(), nil), nil
	}

	header := wsSettings.GetRequestHeader()
	if ed != nil {
		// RawURLEncoding is support by both V2Ray/V2Fly and XRay.
		header.Set("Sec-WebSocket-Protocol", base64.RawURLEncoding.EncodeToString(ed))
	}

	conn, resp, err := dialer.Dial(uri, header)
	if err != nil {
		var reason string
		if resp != nil {
			reason = resp.Status
		}
		return nil, newError("failed to dial to (", uri, "): ", reason).Base(err)
	}

	return newConnection(conn, conn.RemoteAddr(), nil), nil
}

type delayDialConn struct {
	net.Conn
	closed         bool
	dialed         chan bool
	cancel         context.CancelFunc
	ctx            context.Context
	dest           net.Destination
	streamSettings *internet.MemoryStreamConfig
}

func (d *delayDialConn) Write(b []byte) (int, error) {
	if d.closed {
		return 0, io.ErrClosedPipe
	}
	if d.Conn == nil {
		ed := b
		if len(ed) > int(d.streamSettings.ProtocolSettings.(*Config).Ed) {
			ed = nil
		}
		var err error
		if d.Conn, err = dialWebSocket(d.ctx, d.dest, d.streamSettings, ed); err != nil {
			d.Close()
			return 0, newError("failed to dial WebSocket").Base(err)
		}
		d.dialed <- true
		if ed != nil {
			return len(ed), nil
		}
	}
	return d.Conn.Write(b)
}

func (d *delayDialConn) Read(b []byte) (int, error) {
	if d.closed {
		return 0, io.ErrClosedPipe
	}
	if d.Conn == nil {
		select {
		case <-d.ctx.Done():
			return 0, io.ErrUnexpectedEOF
		case <-d.dialed:
		}
	}
	return d.Conn.Read(b)
}

func (d *delayDialConn) Close() error {
	d.closed = true
	d.cancel()
	if d.Conn == nil {
		return nil
	}
	return d.Conn.Close()
}
