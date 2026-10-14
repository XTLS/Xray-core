package outbound_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	. "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport"
)

// closingHandler records whether it was closed.
type closingHandler struct {
	tag    string
	closed atomic.Bool
}

func (h *closingHandler) Start() error                              { return nil }
func (h *closingHandler) Close() error                              { h.closed.Store(true); return nil }
func (h *closingHandler) Tag() string                               { return h.tag }
func (h *closingHandler) Dispatch(context.Context, *transport.Link) {}
func (h *closingHandler) SenderSettings() *serial.TypedMessage      { return nil }
func (h *closingHandler) ProxySettings() *serial.TypedMessage       { return nil }

func TestRemoveHandlerClosesIt(t *testing.T) {
	ohm, err := New(context.Background(), &proxyman.OutboundConfig{})
	common.Must(err)
	h := &closingHandler{tag: "out"}
	common.Must(ohm.AddHandler(context.Background(), h))

	common.Must(ohm.RemoveHandler(context.Background(), "out"))
	if ohm.GetHandler("out") != nil {
		t.Fatal("handler is still there after removal")
	}
	if !h.closed.Load() {
		t.Fatal("removed handler was not closed")
	}
}
