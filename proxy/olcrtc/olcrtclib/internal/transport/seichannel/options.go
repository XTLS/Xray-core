package seichannel

import (
	"fmt"
	"time"

	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/transport"
)

// Options tunes the seichannel transport. Zero values fall back to documented defaults.
type Options struct {
	FPS          int
	BatchSize    int
	FragmentSize int
	AckTimeoutMS int
}

// TransportOptions marks Options as belonging to the transport options family.
func (Options) TransportOptions() {}

// withDefaults fills unset Options fields with the package defaults.
func (o Options) withDefaults() Options {
	if o.FPS <= 0 {
		o.FPS = defaultFPS
	}
	if o.BatchSize <= 0 {
		o.BatchSize = defaultBatchSize
	}
	if o.FragmentSize <= 0 {
		o.FragmentSize = defaultFragmentSize
	}
	if o.AckTimeoutMS <= 0 {
		o.AckTimeoutMS = int(defaultAckTimeout / time.Millisecond)
	}
	return o
}

func optionsFrom(cfg transport.Config) (Options, error) {
	if cfg.Options == nil {
		return Options{}, nil
	}
	opts, ok := cfg.Options.(Options)
	if !ok {
		return Options{}, fmt.Errorf("%w: seichannel: got %T", transport.ErrOptionsTypeMismatch, cfg.Options)
	}
	return opts, nil
}
