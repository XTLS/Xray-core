package dispatcher

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

const minRateLimitBurstBytes = 64 * 1024

var userRateLimiters sync.Map

type userRateLimitKey struct {
	email     string
	direction string
	mbps      uint64
}

func getUserRateLimiter(email, direction string, mbps uint64) *rate.Limiter {
	key := userRateLimitKey{
		email:     email,
		direction: direction,
		mbps:      mbps,
	}
	if limiter, ok := userRateLimiters.Load(key); ok {
		return limiter.(*rate.Limiter)
	}

	bytesPerSecond := mbps * 1000 * 1000 / 8
	if bytesPerSecond == 0 {
		bytesPerSecond = 1
	}
	burst := int(bytesPerSecond)
	if burst < minRateLimitBurstBytes {
		burst = minRateLimitBurstBytes
	}

	limiter := rate.NewLimiter(rate.Limit(bytesPerSecond), burst)
	actual, _ := userRateLimiters.LoadOrStore(key, limiter)
	return actual.(*rate.Limiter)
}

func waitRateLimit(ctx context.Context, limiter *rate.Limiter, bytes int) error {
	if bytes <= 0 {
		return nil
	}
	burst := limiter.Burst()
	for bytes > 0 {
		chunk := bytes
		if chunk > burst {
			chunk = burst
		}
		if err := limiter.WaitN(ctx, chunk); err != nil {
			return err
		}
		bytes -= chunk
	}
	return nil
}

type UserRateLimitWriter struct {
	ctx     context.Context
	limiter *rate.Limiter
	Writer  buf.Writer
}

func NewUserRateLimitWriter(ctx context.Context, email, direction string, mbps uint64, writer buf.Writer) buf.Writer {
	if mbps == 0 || email == "" || writer == nil {
		return writer
	}
	return &UserRateLimitWriter{
		ctx:     ctx,
		limiter: getUserRateLimiter(email, direction, mbps),
		Writer:  writer,
	}
}

func (w *UserRateLimitWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if err := waitRateLimit(w.ctx, w.limiter, int(mb.Len())); err != nil {
		buf.ReleaseMulti(mb)
		return fmt.Errorf("user rate limit wait failed: %w", err)
	}
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *UserRateLimitWriter) Close() error {
	return common.Close(w.Writer)
}

func (w *UserRateLimitWriter) Interrupt() {
	common.Interrupt(w.Writer)
}

type UserRateLimitReader struct {
	ctx     context.Context
	limiter *rate.Limiter
	Reader  buf.Reader
}

func NewUserRateLimitReader(ctx context.Context, email, direction string, mbps uint64, reader buf.Reader) buf.Reader {
	if mbps == 0 || email == "" || reader == nil {
		return reader
	}
	return &UserRateLimitReader{
		ctx:     ctx,
		limiter: getUserRateLimiter(email, direction, mbps),
		Reader:  reader,
	}
}

func (r *UserRateLimitReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if err != nil || mb.IsEmpty() {
		return mb, err
	}
	if waitErr := waitRateLimit(r.ctx, r.limiter, int(mb.Len())); waitErr != nil {
		buf.ReleaseMulti(mb)
		return nil, fmt.Errorf("user rate limit wait failed: %w", waitErr)
	}
	return mb, nil
}

func (r *UserRateLimitReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	timeoutReader, ok := r.Reader.(buf.TimeoutReader)
	if !ok {
		return r.ReadMultiBuffer()
	}
	mb, err := timeoutReader.ReadMultiBufferTimeout(timeout)
	if err != nil || mb.IsEmpty() {
		return mb, err
	}
	if waitErr := waitRateLimit(r.ctx, r.limiter, int(mb.Len())); waitErr != nil {
		buf.ReleaseMulti(mb)
		return nil, fmt.Errorf("user rate limit wait failed: %w", waitErr)
	}
	return mb, nil
}

func (r *UserRateLimitReader) Close() error {
	return common.Close(r.Reader)
}

func (r *UserRateLimitReader) Interrupt() {
	common.Interrupt(r.Reader)
}
