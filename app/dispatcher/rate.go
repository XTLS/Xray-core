package dispatcher

import (
	"context"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
	"strconv"
	"strings"
)

type Writer struct {
	writer  buf.Writer
	limiter *RateLimiter
}

type RateLimiter struct {
	ctx         *context.Context
	sendLimiter *rate.Limiter
	recvLimiter *rate.Limiter
}

func NewRateLimiter(cpCtx *context.Context, d *DefaultDispatcher, userEmail string) *RateLimiter {
	if d.bucket[userEmail] == nil {
		// xui没有 user.Level 试用email字段 加 - 等级
		levelString := strings.Split(userEmail, "-")[1]
		level, _ := strconv.Atoi(levelString)
		var limitInt = 1024 * 1024 * level
		d.bucket[userEmail] = rate.NewLimiter(rate.Limit(limitInt), limitInt*2)
	}
	bucket := d.bucket[userEmail]
	return &RateLimiter{
		ctx:         cpCtx,
		sendLimiter: bucket,
		recvLimiter: bucket,
	}
}

func (l *RateLimiter) RateWait(count int64) {
	if l.sendLimiter != nil && count != 0 {
		_ = l.sendLimiter.WaitN(*l.ctx, int(count))
	} else if l.recvLimiter != nil && count != 0 {
		_ = l.recvLimiter.WaitN(*l.ctx, int(count))
	}
}

func RateWriter(writer buf.Writer, limiter *RateLimiter) buf.Writer {
	return &Writer{
		writer:  writer,
		limiter: limiter,
	}
}

func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.limiter.RateWait(int64(mb.Len()))
	return w.writer.WriteMultiBuffer(mb)
}
