package videochannel

import (
	"fmt"

	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/transport"
)

// Options tunes the videochannel transport. Zero values fall back to documented defaults.
type Options struct {
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

// TransportOptions marks Options as belonging to the transport options family.
func (Options) TransportOptions() {}

func optionsFrom(cfg transport.Config) (Options, error) {
	if cfg.Options == nil {
		return Options{}, nil
	}
	opts, ok := cfg.Options.(Options)
	if !ok {
		return Options{}, fmt.Errorf("%w: videochannel: got %T", transport.ErrOptionsTypeMismatch, cfg.Options)
	}
	return opts, nil
}
