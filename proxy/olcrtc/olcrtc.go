// Package olcrtc integrates the olcRTC encrypted TCP-over-WebRTC tunnel
// (github.com/openlibrecommunity/olcrtc) into Xray as a proxy protocol.
//
// It provides:
//
//   - an outbound (ClientConfig / "olcrtc"): each outbound connection is
//     multiplexed as a stream over a shared WebRTC carrier to a room, and the
//     olcrtc server on the other side exits to the internet.
//   - an inbound (ServerConfig / "olcrtc"): a self-driven handler that joins the
//     same room, accepts tunnel streams and dispatches their targets through
//     Xray's router (so routing, DNS, sniffing and stats all apply).
//
// Traffic is disguised as an ordinary video call on an allowed SFU service
// (Jitsi, Yandex Telemost, WbStream) and additionally encrypted with a shared
// XChaCha20-Poly1305 key.
package olcrtc

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/bridge"
)

func init() {
	// Outbound (client).
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
	// Inbound (server). The handler is self-driven: it dials out to the carrier
	// rather than listening on a socket, so mark its config type accordingly.
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
	proxy.RegisterSelfDrivenInbound((*ServerConfig)(nil))
}

// clientBridgeConfig maps the outbound proto config to a bridge.Config.
func clientBridgeConfig(c *ClientConfig) bridge.Config {
	return bridge.Config{
		Provider:           c.GetProvider(),
		Transport:          c.GetTransport(),
		RoomID:             c.GetRoomId(),
		KeyHex:             c.GetKey(),
		DNSServer:          c.GetDnsServer(),
		AuthToken:          c.GetAuthToken(),
		Engine:             c.GetEngine(),
		URL:                c.GetUrl(),
		Token:              c.GetToken(),
		VP8:                &bridge.VP8Options{FPS: int(c.GetVp8Fps()), BatchSize: int(c.GetVp8BatchSize())},
		SEI:                seiOptions(c.GetSeiFps(), c.GetSeiBatchSize(), c.GetSeiFragmentSize(), c.GetSeiAckTimeoutMs()),
		Video:              videoOptions(c),
		LivenessInterval:   c.GetLivenessInterval(),
		LivenessTimeout:    c.GetLivenessTimeout(),
		LivenessFailures:   int(c.GetLivenessFailures()),
		MaxSessionDuration: c.GetMaxSessionDuration(),
		DeviceID:           c.GetDeviceId(),
		DeviceIDPath:       c.GetDeviceIdPath(),
	}
}

// serverBridgeConfig maps the inbound proto config to a bridge.Config.
func serverBridgeConfig(c *ServerConfig) bridge.Config {
	return bridge.Config{
		Provider:           c.GetProvider(),
		Transport:          c.GetTransport(),
		RoomID:             c.GetRoomId(),
		KeyHex:             c.GetKey(),
		DNSServer:          c.GetDnsServer(),
		AuthToken:          c.GetAuthToken(),
		Engine:             c.GetEngine(),
		URL:                c.GetUrl(),
		Token:              c.GetToken(),
		VP8:                &bridge.VP8Options{FPS: int(c.GetVp8Fps()), BatchSize: int(c.GetVp8BatchSize())},
		SEI:                seiOptions(c.GetSeiFps(), c.GetSeiBatchSize(), c.GetSeiFragmentSize(), c.GetSeiAckTimeoutMs()),
		Video: &bridge.VideoOptions{
			Width:      int(c.GetVideoWidth()),
			Height:     int(c.GetVideoHeight()),
			FPS:        int(c.GetVideoFps()),
			Bitrate:    c.GetVideoBitrate(),
			HW:         c.GetVideoHw(),
			QRSize:     int(c.GetVideoQrSize()),
			QRRecovery: c.GetVideoQrRecovery(),
			Codec:      c.GetVideoCodec(),
			TileModule: int(c.GetVideoTileModule()),
			TileRS:     int(c.GetVideoTileRs()),
		},
		LivenessInterval:   c.GetLivenessInterval(),
		LivenessTimeout:    c.GetLivenessTimeout(),
		LivenessFailures:   int(c.GetLivenessFailures()),
		MaxSessionDuration: c.GetMaxSessionDuration(),
	}
}

func seiOptions(fps, batch, frag, ackMs int32) *bridge.SEIOptions {
	return &bridge.SEIOptions{
		FPS:          int(fps),
		BatchSize:    int(batch),
		FragmentSize: int(frag),
		AckTimeoutMS: int(ackMs),
	}
}

func videoOptions(c *ClientConfig) *bridge.VideoOptions {
	return &bridge.VideoOptions{
		Width:      int(c.GetVideoWidth()),
		Height:     int(c.GetVideoHeight()),
		FPS:        int(c.GetVideoFps()),
		Bitrate:    c.GetVideoBitrate(),
		HW:         c.GetVideoHw(),
		QRSize:     int(c.GetVideoQrSize()),
		QRRecovery: c.GetVideoQrRecovery(),
		Codec:      c.GetVideoCodec(),
		TileModule: int(c.GetVideoTileModule()),
		TileRS:     int(c.GetVideoTileRs()),
	}
}
