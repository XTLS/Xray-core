package proxy

import (
	"context"
	"math/rand/v2"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
)

// wait to drain all the possible incoming UDP data
// because re-established QUIC UDP may bypass the sniffer
func DropUDP(ctx context.Context, reader buf.Reader) {
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
	}, time.Duration(30+rand.N(60))*time.Second)
	context.AfterFunc(ctx, func() {
		common.Interrupt(reader)
	})
	buf.Copy(reader, buf.Discard, buf.UpdateActivity(timer))
}
