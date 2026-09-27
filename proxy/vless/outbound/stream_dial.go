package outbound

import (
	"context"
	"time"

	xctx "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// dialServer retains the same preconnection and retry behavior for old and
// admitted ordinary streams.
func (h *Handler) dialServer(ctx context.Context, dialer internet.Dialer) (stat.Connection, error) {
	rec := h.server
	var conn stat.Connection

	if h.testpre > 0 && h.reverse == nil {
		h.initpre.Do(func() {
			h.preConns = make(chan *ConnExpire)
			for range h.testpre { // TODO: randomize
				go func() {
					defer func() { recover() }()
					ctx := xctx.ContextWithID(context.Background(), session.NewID())
					for {
						conn, err := dialer.Dial(ctx, rec.Destination)
						if err != nil {
							errors.LogWarningInner(ctx, err, "pre-connect failed")
							continue
						}
						h.preConns <- &ConnExpire{Conn: conn, Expire: time.Now().Add(time.Minute * 2)} // TODO: customize & randomize
						time.Sleep(time.Millisecond * 200)                                             // TODO: customize & randomize
					}
				}()
			}
		})
		for {
			var connTime *ConnExpire
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case connTime = <-h.preConns:
			}
			if connTime == nil {
				return nil, errors.New("closed handler")
			}
			if time.Now().Before(connTime.Expire) {
				conn = connTime.Conn
				break
			}
			connTime.Conn.Close()
		}
	}

	if conn == nil {
		if err := retry.ExponentialBackoffContext(ctx, 5, 200).On(func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			var err error
			conn, err = dialer.Dial(ctx, rec.Destination)
			if err != nil {
				return err
			}
			return nil
		}); err != nil {
			return nil, errors.New("failed to find an available destination").Base(err)
		}
	}
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}
