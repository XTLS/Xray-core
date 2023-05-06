package dispatcher

import (
	"context"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
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

func NewRateLimiter(cpCtx *context.Context, d *DefaultDispatcher, user *protocol.MemoryUser) *RateLimiter {
	if d.bucket[user.Email] == nil {
		// xui没有 user.Level 试用email字段 加 - 等级
		levelString := strings.Split(user.Email, "-")[1]
		level, _ := strconv.Atoi(levelString)
		var limitInt = 1024 * 1024 * level
		d.bucket[user.Email] = rate.NewLimiter(rate.Limit(limitInt), limitInt*2)
	}
	bucket := d.bucket[user.Email]
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
