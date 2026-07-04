// Package bridge is the public surface of the vendored olcrtc library. It
// exposes exactly what the Xray proxy needs - an outbound client that dials
// targets over the encrypted WebRTC carrier, and a server that accepts tunnel
// streams and hands their egress to a caller-supplied dialer - while keeping
// the rest of olcrtc (internal/*) private to this subtree.
package bridge

import (
	"context"
	"net"
	"sync"

	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/app/session"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/client"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/server"
)

// DialFunc is the server-side egress hook. It is called with each tunnel
// stream's CONNECT target and must return a net.Conn to pipe against the stream.
type DialFunc = server.DialFunc

// VP8Options tunes the vp8channel transport.
type VP8Options struct {
	FPS       int
	BatchSize int
}

// SEIOptions tunes the seichannel transport.
type SEIOptions struct {
	FPS          int
	BatchSize    int
	FragmentSize int
	AckTimeoutMS int
}

// VideoOptions tunes the videochannel transport.
type VideoOptions struct {
	Width      int
	Height     int
	FPS        int
	Bitrate    string
	HW         string
	QRSize     int
	QRRecovery string
	Codec      string
	TileModule int
	TileRS     int
}

// Config describes an olcrtc tunnel. The same struct configures both the
// outbound client and the inbound server; fields that only apply to one side
// are documented as such.
type Config struct {
	// Provider selects the disguise/auth provider: "jitsi", "telemost",
	// "wbstream", or "none" for direct engine mode.
	Provider string
	// Transport selects the WebRTC carrier encoding: "datachannel",
	// "vp8channel", "seichannel", or "videochannel".
	Transport string
	// RoomID is the conference room reference for the provider. Required unless
	// Provider is "none".
	RoomID string
	// KeyHex is the shared 64-hex-char (32-byte) XChaCha20-Poly1305 key.
	KeyHex string
	// DNSServer is the resolver used to reach the SFU, e.g. "8.8.8.8:53".
	DNSServer string
	// AuthToken is an optional pre-issued provider account token (e.g. WbStream).
	AuthToken string

	// Direct engine mode (Provider == "none").
	Engine string // "livekit", "goolom", "jitsi"
	URL    string
	Token  string

	// Optional transport tuning (nil = provider defaults).
	VP8   *VP8Options
	SEI   *SEIOptions
	Video *VideoOptions

	// Optional liveness / lifecycle tuning (empty = defaults).
	LivenessInterval   string
	LivenessTimeout    string
	LivenessFailures   int
	MaxSessionDuration string

	// Client-only identity. DeviceID (or a DeviceIDPath to persist an
	// auto-generated one) is echoed to the server's auth hook; Claims is a
	// free-form bag forwarded verbatim to that hook.
	DeviceID     string
	DeviceIDPath string
	Claims       map[string]any
}

func (c Config) toSession() session.Config {
	sc := session.Config{
		Transport:          c.Transport,
		Auth:               c.Provider,
		AuthToken:          c.AuthToken,
		Engine:             c.Engine,
		URL:                c.URL,
		Token:              c.Token,
		RoomID:             c.RoomID,
		KeyHex:             c.KeyHex,
		DNSServer:          c.DNSServer,
		LivenessInterval:   c.LivenessInterval,
		LivenessTimeout:    c.LivenessTimeout,
		LivenessFailures:   c.LivenessFailures,
		MaxSessionDuration: c.MaxSessionDuration,
		DeviceID:           c.DeviceID,
		DeviceIDPath:       c.DeviceIDPath,
		Claims:             c.Claims,
	}
	if c.VP8 != nil {
		sc.VP8 = session.VP8Config{FPS: c.VP8.FPS, BatchSize: c.VP8.BatchSize}
	}
	if c.SEI != nil {
		sc.SEI = session.SEIConfig{
			FPS:          c.SEI.FPS,
			BatchSize:    c.SEI.BatchSize,
			FragmentSize: c.SEI.FragmentSize,
			AckTimeoutMS: c.SEI.AckTimeoutMS,
		}
	}
	if c.Video != nil {
		sc.Video = session.VideoConfig{
			Width:      c.Video.Width,
			Height:     c.Video.Height,
			FPS:        c.Video.FPS,
			Bitrate:    c.Video.Bitrate,
			HW:         c.Video.HW,
			QRSize:     c.Video.QRSize,
			QRRecovery: c.Video.QRRecovery,
			Codec:      c.Video.Codec,
			TileModule: c.Video.TileModule,
			TileRS:     c.Video.TileRS,
		}
	}
	return sc
}

var registerOnce sync.Once

// RegisterDefaults registers the built-in carriers, engines and transports. It
// is safe to call multiple times and is invoked automatically by StartClient
// and RunServer, but embedders may call it explicitly at startup.
func RegisterDefaults() { registerOnce.Do(session.RegisterDefaults) }

// Client is a live outbound olcrtc tunnel. It maintains the shared WebRTC
// carrier and opens one multiplexed stream per DialContext call.
type Client struct {
	t *client.Tunnel
}

// StartClient brings up the carrier described by cfg and returns a ready Client.
// The tunnel runs until Close is called or ctx is cancelled.
func StartClient(ctx context.Context, cfg Config) (*Client, error) {
	RegisterDefaults()
	sc := cfg.toSession()
	if err := session.ValidateTunnel(sc); err != nil {
		return nil, err
	}
	cc, err := session.ClientConfig(sc)
	if err != nil {
		return nil, err
	}
	t, err := client.StartTunnel(ctx, cc)
	if err != nil {
		return nil, err
	}
	return &Client{t: t}, nil
}

// DialContext opens a tunnel stream to addr:port and returns a net.Conn for it.
func (c *Client) DialContext(ctx context.Context, addr string, port int) (net.Conn, error) {
	return c.t.DialContext(ctx, addr, port)
}

// Close tears the tunnel down.
func (c *Client) Close() error { return c.t.Close() }

// RunServer runs the inbound olcrtc tunnel described by cfg. Every accepted
// tunnel stream's CONNECT target is passed to dial, whose returned net.Conn is
// piped against the stream. RunServer blocks until ctx is cancelled or the
// carrier ends.
func RunServer(ctx context.Context, cfg Config, dial DialFunc) error {
	RegisterDefaults()
	sc := cfg.toSession()
	if err := session.ValidateTunnel(sc); err != nil {
		return err
	}
	scfg, err := session.ServerConfig(sc, dial)
	if err != nil {
		return err
	}
	return server.Run(ctx, scfg)
}
