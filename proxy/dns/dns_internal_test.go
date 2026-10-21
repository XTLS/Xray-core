package dns

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/dns/dnsmessage"
)

type manyIPsClient []net.IP

func (manyIPsClient) Type() interface{} { return dns.ClientType() }
func (manyIPsClient) Start() error      { return nil }
func (manyIPsClient) Close() error      { return nil }
func (c manyIPsClient) LookupIP(string, dns.IPOption) ([]net.IP, uint32, error) {
	return c, 60, nil
}

type replyWriter struct{ reply *buf.Buffer }

func (w *replyWriter) WriteMessage(b *buf.Buffer) error {
	w.reply = b
	return nil
}

func TestHandleIPQueryManyIPs(t *testing.T) {
	ips := make(manyIPsClient, 1000)
	for i := range ips {
		ips[i] = net.IP{10, 0, byte(i >> 8), byte(i)}
	}
	h := &Handler{client: ips}
	timer := signal.CancelAfterInactivity(context.Background(), func() {}, time.Minute)
	longest := strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 61) + "."

	for _, qType := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		w := &replyWriter{}
		h.handleIPQuery(1, qType, longest, w, timer)
		var msg dnsmessage.Message
		common.Must(msg.Unpack(w.reply.Bytes()))
		if len(msg.Answers) == 0 {
			t.Fatalf("%v: no answers", qType)
		}
		w.reply.Release()
	}
}
