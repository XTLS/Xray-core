package server

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/proxy/hysteria2/hycore/v2/errors"
	"github.com/xtls/xray-core/proxy/hysteria2/hycore/v2/internal/pmtud"
	"github.com/xtls/xray-core/proxy/hysteria2/hycore/v2/internal/utils"
	"github.com/apernet/quic-go"
)

const (
	defaultStreamReceiveWindow = 8388608                            // 8MB
	defaultConnReceiveWindow   = defaultStreamReceiveWindow * 5 / 2 // 20MB
	defaultMaxIdleTimeout      = 30 * time.Second
	defaultMaxIncomingStreams  = 1024
	defaultUDPIdleTimeout      = 60 * time.Second
)

type Config struct {
	TLSConfig             TLSConfig
	QUICConfig            QUICConfig
	Conn                  net.PacketConn
	RequestHook           RequestHook
	Outbound              Outbound
	BandwidthConfig       BandwidthConfig
	IgnoreClientBandwidth bool
	DisableUDP            bool
	UDPIdleTimeout        time.Duration
	Authenticator         Authenticator
	EventLogger           EventLogger
	TrafficLogger         TrafficLogger
	MasqHandler           http.Handler
}

// fill fills the fields that are not set by the user with default values when possible,
// and returns an error if the user has not set a required field, or if a field is invalid.
func (c *Config) fill() error {
	if len(c.TLSConfig.Certificates) == 0 && c.TLSConfig.GetCertificate == nil {
		return errors.ConfigError{Field: "TLSConfig", Reason: "must set at least one of Certificates or GetCertificate"}
	}
	if c.QUICConfig.InitialStreamReceiveWindow == 0 {
		c.QUICConfig.InitialStreamReceiveWindow = defaultStreamReceiveWindow
	} else if c.QUICConfig.InitialStreamReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.InitialStreamReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.MaxStreamReceiveWindow == 0 {
		c.QUICConfig.MaxStreamReceiveWindow = defaultStreamReceiveWindow
	} else if c.QUICConfig.MaxStreamReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.MaxStreamReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.InitialConnectionReceiveWindow == 0 {
		c.QUICConfig.InitialConnectionReceiveWindow = defaultConnReceiveWindow
	} else if c.QUICConfig.InitialConnectionReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.InitialConnectionReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.MaxConnectionReceiveWindow == 0 {
		c.QUICConfig.MaxConnectionReceiveWindow = defaultConnReceiveWindow
	} else if c.QUICConfig.MaxConnectionReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.MaxConnectionReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.MaxIdleTimeout == 0 {
		c.QUICConfig.MaxIdleTimeout = defaultMaxIdleTimeout
	} else if c.QUICConfig.MaxIdleTimeout < 4*time.Second || c.QUICConfig.MaxIdleTimeout > 120*time.Second {
		return errors.ConfigError{Field: "QUICConfig.MaxIdleTimeout", Reason: "must be between 4s and 120s"}
	}
	if c.QUICConfig.MaxIncomingStreams == 0 {
		c.QUICConfig.MaxIncomingStreams = defaultMaxIncomingStreams
	} else if c.QUICConfig.MaxIncomingStreams < 8 {
		return errors.ConfigError{Field: "QUICConfig.MaxIncomingStreams", Reason: "must be at least 8"}
	}
	c.QUICConfig.DisablePathMTUDiscovery = c.QUICConfig.DisablePathMTUDiscovery || pmtud.DisablePathMTUDiscovery
	if c.Conn == nil {
		return errors.ConfigError{Field: "Conn", Reason: "must be set"}
	}
	if c.Outbound == nil {
		c.Outbound = &defaultOutbound{}
	}
	if c.BandwidthConfig.MaxTx != 0 && c.BandwidthConfig.MaxTx < 65536 {
		return errors.ConfigError{Field: "BandwidthConfig.MaxTx", Reason: "must be at least 65536"}
	}
	if c.BandwidthConfig.MaxRx != 0 && c.BandwidthConfig.MaxRx < 65536 {
		return errors.ConfigError{Field: "BandwidthConfig.MaxRx", Reason: "must be at least 65536"}
	}
	if c.UDPIdleTimeout == 0 {
		c.UDPIdleTimeout = defaultUDPIdleTimeout
	} else if c.UDPIdleTimeout < 2*time.Second || c.UDPIdleTimeout > 600*time.Second {
		return errors.ConfigError{Field: "UDPIdleTimeout", Reason: "must be between 2s and 600s"}
	}
	if c.Authenticator == nil {
		return errors.ConfigError{Field: "Authenticator", Reason: "must be set"}
	}
	return nil
}

// TLSConfig contains the TLS configuration fields that we want to expose to the user.
type TLSConfig struct {
	Certificates   []tls.Certificate
	GetCertificate func(info *tls.ClientHelloInfo) (*tls.Certificate, error)
	ClientCAs      *x509.CertPool
}

// QUICConfig contains the QUIC configuration fields that we want to expose to the user.
type QUICConfig struct {
	InitialStreamReceiveWindow     uint64
	MaxStreamReceiveWindow         uint64
	InitialConnectionReceiveWindow uint64
	MaxConnectionReceiveWindow     uint64
	MaxIdleTimeout                 time.Duration
	MaxIncomingStreams             int64
	DisablePathMTUDiscovery        bool // The server may still override this to true on unsupported platforms.
}

// RequestHook allows filtering and modifying requests before the server connects to the remote.
// A request will only be hooked if Check returns true.
// The returned byte slice, if not empty, will be sent to the remote before proxying - this is
// mainly for "putting back" the content read from the client for sniffing, etc.
// Return a non-nil error to abort the connection.
// Note that due to the current architectural limitations, it can only inspect the first packet
// of a UDP connection. It also cannot put back any data as the first packet is always sent as-is.
type RequestHook interface {
	Check(isUDP bool, reqAddr string) bool
	TCP(stream HyStream, reqAddr *string) ([]byte, error)
	UDP(data []byte, reqAddr *string) error
}

// Outbound provides the implementation of how the server should connect to remote servers.
// Although UDP includes a reqAddr, the implementation does not necessarily have to use it
// to make a "connected" UDP connection that does not accept packets from other addresses.
// In fact, the default implementation simply uses net.ListenUDP for a "full-cone" behavior.
type Outbound interface {
	TCP(reqAddr string) (net.Conn, error)
	UDP(reqAddr string) (UDPConn, error)
}

// UDPConn is like net.PacketConn, but uses string for addresses.
type UDPConn interface {
	ReadFrom(b []byte) (int, string, error)
	WriteTo(b []byte, addr string) (int, error)
	Close() error
}

type defaultOutbound struct{}

var defaultOutboundDialer = net.Dialer{
	Timeout: 10 * time.Second,
}

func (o *defaultOutbound) TCP(reqAddr string) (net.Conn, error) {
	return defaultOutboundDialer.Dial("tcp", reqAddr)
}

func (o *defaultOutbound) UDP(reqAddr string) (UDPConn, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return &defaultUDPConn{conn}, nil
}

type defaultUDPConn struct {
	*net.UDPConn
}

func (c *defaultUDPConn) ReadFrom(b []byte) (int, string, error) {
	n, addr, err := c.UDPConn.ReadFrom(b)
	if addr != nil {
		return n, addr.String(), err
	} else {
		return n, "", err
	}
}

func (c *defaultUDPConn) WriteTo(b []byte, addr string) (int, error) {
	uAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return 0, err
	}
	return c.UDPConn.WriteTo(b, uAddr)
}

// BandwidthConfig describes the maximum bandwidth that the server can use, in bytes per second.
type BandwidthConfig struct {
	MaxTx uint64
	MaxRx uint64
}

// Authenticator is an interface that provides authentication logic.
type Authenticator interface {
	Authenticate(addr net.Addr, auth string, tx uint64) (ok bool, id string)
}

// EventLogger is an interface that provides logging logic.
type EventLogger interface {
	Connect(addr net.Addr, id string, tx uint64)
	Disconnect(addr net.Addr, id string, err error)
	TCPRequest(addr net.Addr, id, reqAddr string)
	TCPError(addr net.Addr, id, reqAddr string, err error)
	UDPRequest(addr net.Addr, id string, sessionID uint32, reqAddr string)
	UDPError(addr net.Addr, id string, sessionID uint32, err error)
}

type HyStream interface {
	StreamID() quic.StreamID
	Read(p []byte) (n int, err error)
	Write(p []byte) (n int, err error)
	Close() error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	SetDeadline(t time.Time) error
}

// TrafficLogger is an interface that provides traffic logging logic.
// Tx/Rx in this context refers to the server-remote (proxy target) perspective.
// Tx is the bytes sent from the server to the remote.
// Rx is the bytes received by the server from the remote.
// Apart from logging, the Log function can also return false to signal
// that the client should be disconnected. This can be used to implement
// bandwidth limits or post-connection authentication, for example.
// The implementation of this interface must be thread-safe.
type TrafficLogger interface {
	LogTraffic(id string, tx, rx uint64) (ok bool)
	LogOnlineState(id string, online bool)
	TraceStream(stream HyStream, stats *StreamStats)
	UntraceStream(stream HyStream)
}

type StreamState int

const (
	// StreamStateInitial indicates the initial state of a stream.
	// Client has opened the stream, but we have not received the proxy request yet.
	StreamStateInitial StreamState = iota

	// StreamStateHooking indicates that the hook (usually sniff) is processing.
	// Client has sent the proxy request, but sniff requires more data to complete.
	StreamStateHooking

	// StreamStateConnecting indicates that we are connecting to the proxy target.
	StreamStateConnecting

	// StreamStateEstablished indicates the proxy is established.
	StreamStateEstablished

	// StreamStateClosed indicates the stream is closed.
	StreamStateClosed
)

func (s StreamState) String() string {
	switch s {
	case StreamStateInitial:
		return "init"
	case StreamStateHooking:
		return "hook"
	case StreamStateConnecting:
		return "connect"
	case StreamStateEstablished:
		return "estab"
	case StreamStateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

type StreamStats struct {
	State utils.Atomic[StreamState]

	AuthID      string
	ConnID      uint32
	InitialTime time.Time

	ReqAddr       utils.Atomic[string]
	HookedReqAddr utils.Atomic[string]

	Tx atomic.Uint64
	Rx atomic.Uint64

	LastActiveTime utils.Atomic[time.Time]
}

func (s *StreamStats) setHookedReqAddr(addr string) {
	if addr != s.ReqAddr.Load() {
		s.HookedReqAddr.Store(addr)
	}
}
