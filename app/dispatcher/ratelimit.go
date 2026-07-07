package dispatcher

import (
	"context"
	"sync"

	"golang.org/x/time/rate"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

// UserBytesPerSec returns the aggregate byte/s cap for a user, or 0 for
// "unlimited". This is the single place to customize per-user limits: return a
// constant, switch on level for tiers, or look up an email->rate map you load
// from a file/DB. It applies uniformly across every protocol (vless, hysteria,
// olcrtc, …) and across all of a user's devices, because the limiter is keyed by
// email at the dispatcher — the one point every user connection converges on.
//
// Default: 10 MB/s. Set to 0 to disable.
func UserBytesPerSec(email string, level uint32) float64 {
	return 10 * 1024 * 1024
}

var (
	limitersMu sync.Mutex
	limiters   = map[string]*rate.Limiter{} // key: email|direction
)

// userLimiter returns ONE shared limiter per (email, direction). Sharing is the
// point: every connection and every device for that user pulls from the same
// token bucket, so the cap is aggregate across all of them.
func userLimiter(email, dir string, bps float64) *rate.Limiter {
	if bps <= 0 {
		return nil
	}
	key := email + "|" + dir
	limitersMu.Lock()
	defer limitersMu.Unlock()
	l := limiters[key]
	if l == nil {
		burst := int(bps) // 1s bucket; keep >= a few MB so a single write never exceeds it
		if burst < 1<<20 {
			burst = 1 << 20
		}
		l = rate.NewLimiter(rate.Limit(bps), burst)
		limiters[key] = l
	}
	return l
}

// rateLimitWriter throttles a buf.Writer to a shared per-user token bucket by
// blocking before each write; the resulting backpressure propagates through the
// pipe and slows the TCP sender to the target rate.
type rateLimitWriter struct {
	ctx     context.Context
	writer  buf.Writer
	limiter *rate.Limiter
}

func (w *rateLimitWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if n := int(mb.Len()); n > 0 {
		if err := w.limiter.WaitN(w.ctx, n); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}
	return w.writer.WriteMultiBuffer(mb)
}

func (w *rateLimitWriter) Close() error { return common.Close(w.writer) }

func (w *rateLimitWriter) Interrupt() { common.Interrupt(w.writer) }

// rateLimitLink wraps a link's writers with per-user limiters when the user has
// a finite cap. up is client->server (upload), down is server->client
// (download); each gets an independent bucket so upload and download are each
// capped at bps. Pass the same key for a combined cap instead.
func rateLimitLink(ctx context.Context, email string, level uint32, up, down buf.Writer) (buf.Writer, buf.Writer) {
	bps := UserBytesPerSec(email, level)
	if bps <= 0 {
		return up, down
	}
	if l := userLimiter(email, "ul", bps); l != nil {
		up = &rateLimitWriter{ctx: ctx, writer: up, limiter: l}
	}
	if l := userLimiter(email, "dl", bps); l != nil {
		down = &rateLimitWriter{ctx: ctx, writer: down, limiter: l}
	}
	return up, down
}
