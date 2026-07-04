package session

import (
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/transport"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/transport/seichannel"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/transport/videochannel"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/transport/vp8channel"
)

// buildTransportOptions packs per-transport tuning fields from cfg into the
// typed Options value the chosen transport expects. Transports without
// tunable options (datachannel) return nil.
func buildTransportOptions(cfg Config) transport.Options {
	switch cfg.Transport {
	case transportVideo:
		return videochannel.Options{
			Width:      cfg.Video.Width,
			Height:     cfg.Video.Height,
			FPS:        cfg.Video.FPS,
			Bitrate:    cfg.Video.Bitrate,
			HW:         cfg.Video.HW,
			QRSize:     cfg.Video.QRSize,
			QRRecovery: cfg.Video.QRRecovery,
			Codec:      cfg.Video.Codec,
			TileModule: cfg.Video.TileModule,
			TileRS:     cfg.Video.TileRS,
		}
	case transportVP8:
		return vp8channel.Options{
			FPS:       cfg.VP8.FPS,
			BatchSize: cfg.VP8.BatchSize,
		}
	case transportSEI:
		return seichannel.Options{
			FPS:          cfg.SEI.FPS,
			BatchSize:    cfg.SEI.BatchSize,
			FragmentSize: cfg.SEI.FragmentSize,
			AckTimeoutMS: cfg.SEI.AckTimeoutMS,
		}
	default:
		return nil
	}
}
