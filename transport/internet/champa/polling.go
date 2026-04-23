package champa

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"time"

	xerrors "github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/champa/internal/encapsulation"
	"github.com/xtls/xray-core/transport/internet/champa/internal/turbotunnel"
)

const (
	initPollDelay       = 1 * time.Second
	maxPollDelay        = 10 * time.Second
	pollDelayMultiplier = 2.0
	pollTimeout         = 30 * time.Second

	requestsPerSecondMax                    = 5.0
	requestsPerSecondBurst                  = requestsPerSecondMax * 2
	requestsPerSecondRateOfIncrease         = 1.0 / 10.0
	requestsPerSecondMultiplicativeDecrease = 0.5
)

type pollFunc func(context.Context, []byte) (io.ReadCloser, error)

// pollingPacketConn implements net.PacketConn over an abstract poll function.
// Outgoing packets to remoteAddr are batched, encapsulated, and handed to poll;
// the response body is decoded back into incoming packets. Lifted from
// champa/champa-client/pollingpacketconn.go with logging removed in favor of
// xray's errors logger.
type pollingPacketConn struct {
	remoteAddr net.Addr
	clientID   turbotunnel.ClientID
	ctx        context.Context
	cancel     context.CancelFunc
	*turbotunnel.QueuePacketConn
}

func newPollingPacketConn(ctx context.Context, remoteAddr net.Addr, poll pollFunc) *pollingPacketConn {
	clientID := turbotunnel.NewClientID()
	pctx, cancel := context.WithCancel(ctx)
	c := &pollingPacketConn{
		remoteAddr:      remoteAddr,
		clientID:        clientID,
		ctx:             pctx,
		cancel:          cancel,
		QueuePacketConn: turbotunnel.NewQueuePacketConn(clientID, 0),
	}
	go func() {
		if err := c.pollLoop(poll); err != nil {
			xerrors.LogInfo(pctx, "champa pollLoop: ", err)
		}
	}()
	return c
}

func (c *pollingPacketConn) Close() error {
	c.cancel()
	return c.QueuePacketConn.Close()
}

func (c *pollingPacketConn) pollLoop(poll pollFunc) error {
	const maxPayloadLength = 2048

	rateLimit := newRateLimiter(time.Now(), requestsPerSecondMax, requestsPerSecondBurst, requestsPerSecondRateOfIncrease)

	pollDelay := initPollDelay
	pollTimer := time.NewTimer(pollDelay)
	for {
		var p []byte
		unstash := c.QueuePacketConn.Unstash(c.remoteAddr)
		outgoing := c.QueuePacketConn.OutgoingQueue(c.remoteAddr)
		pollTimerExpired := false
		select {
		case <-c.ctx.Done():
			return nil
		default:
			select {
			case <-c.ctx.Done():
				return nil
			case p = <-unstash:
			default:
				select {
				case <-c.ctx.Done():
					return nil
				case p = <-unstash:
				case p = <-outgoing:
				default:
					select {
					case <-c.ctx.Done():
						return nil
					case p = <-unstash:
					case p = <-outgoing:
					case <-pollTimer.C:
						pollTimerExpired = true
					}
				}
			}
		}

		if pollTimerExpired {
			pollDelay = time.Duration(float64(pollDelay) * pollDelayMultiplier)
			if pollDelay > maxPollDelay {
				pollDelay = maxPollDelay
			}
		} else {
			if !pollTimer.Stop() {
				<-pollTimer.C
			}
			pollDelay = initPollDelay
		}
		pollTimer.Reset(pollDelay)

		var payload bytes.Buffer
		payload.Write(c.clientID[:])

		first := true
		for len(p) > 0 && (first || payload.Len()+len(p) <= maxPayloadLength) {
			first = false
			encapsulation.WriteData(&payload, p)
			select {
			case p = <-outgoing:
			default:
				p = nil
			}
		}
		if len(p) > 0 {
			c.QueuePacketConn.Stash(p, c.remoteAddr)
		}

		now := time.Now()
		if limited, _ := rateLimit.IsLimited(now); limited {
			continue
		}
		rateLimit.Take(now, 1.0)

		go func() {
			ctx, cancel := context.WithTimeout(c.ctx, pollTimeout)
			defer cancel()
			body, err := poll(ctx, payload.Bytes())
			if err != nil {
				xerrors.LogInfo(c.ctx, "champa poll error, reducing rate: ", err)
				rateLimit.MultiplicativeDecrease(now, requestsPerSecondMultiplicativeDecrease)
				return
			}
			defer body.Close()
			if err := c.processIncoming(body); err != nil {
				xerrors.LogInfo(c.ctx, "champa processIncoming: ", err)
			}
		}()
	}
}

func (c *pollingPacketConn) processIncoming(body io.Reader) error {
	lr := io.LimitReader(body, 500*1024)
	for {
		p, err := encapsulation.ReadData(lr)
		if err != nil {
			if err == io.EOF && lr.(*io.LimitedReader).N == 0 {
				err = errors.New("response body too large")
			} else if err == io.EOF {
				err = nil
			}
			return err
		}
		c.QueuePacketConn.QueueIncoming(p, c.remoteAddr)
	}
}

// rateLimiter is a leaky-bucket limiter. Lifted from champa/champa-client/ratelimit.go.
type rateLimiter struct {
	rate               float64
	max                float64
	rateRateOfIncrease float64
	cur                float64
	lastUpdate         time.Time
}

func newRateLimiter(now time.Time, rate, max, rateRateOfIncrease float64) *rateLimiter {
	return &rateLimiter{
		rate:               rate,
		max:                max,
		rateRateOfIncrease: rateRateOfIncrease,
		lastUpdate:         now,
	}
}

func (rl *rateLimiter) update(now time.Time) {
	if now.Before(rl.lastUpdate) {
		return
	}
	elapsed := now.Sub(rl.lastUpdate).Seconds()
	rl.lastUpdate = now
	rl.cur = rl.cur + rl.rate*elapsed
	if rl.cur > rl.max {
		rl.cur = rl.max
	}
	rl.rate += rl.rateRateOfIncrease * elapsed
}

func (rl *rateLimiter) IsLimited(now time.Time) (bool, time.Duration) {
	rl.update(now)
	if rl.cur < 0.0 {
		return true, time.Duration(-rl.cur / rl.rate * 1e9)
	}
	return false, 0
}

func (rl *rateLimiter) Take(now time.Time, amount float64) {
	rl.update(now)
	rl.cur -= amount
}

func (rl *rateLimiter) MultiplicativeDecrease(now time.Time, factor float64) {
	rl.update(now)
	rl.rate *= factor
	rl.cur = 0.0
}
