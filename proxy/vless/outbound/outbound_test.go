package outbound

import (
	"context"
	gonet "net"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

// countingDialer counts dials and gives connections whose other side is already closed
type countingDialer struct {
	dials int
}

func (d *countingDialer) Dial(context.Context, net.Destination) (stat.Connection, error) {
	d.dials++
	client, server := gonet.Pipe()
	server.Close()
	return client, nil
}

func (d *countingDialer) DestIpAddress() net.IP { return nil }

func (d *countingDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

func processWithFlow(t *testing.T, flow string, target net.Destination) (int, error) {
	t.Helper()
	id := uuid.New()
	h := &Handler{
		server: &protocol.ServerSpec{
			Destination: net.TCPDestination(net.LocalHostIP, 443),
			User:        &protocol.MemoryUser{Account: &vless.MemoryAccount{ID: protocol.NewID(id), Flow: flow}},
		},
		policyManager: policy.DefaultManager{},
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: target}})
	uplinkReader, uplinkWriter := pipe.New()
	downlinkReader, downlinkWriter := pipe.New()
	defer uplinkWriter.Close()
	defer downlinkReader.Interrupt()
	d := &countingDialer{}
	err := h.Process(ctx, &transport.Link{Reader: uplinkReader, Writer: downlinkWriter}, d)
	return d.dials, err
}

func TestVisionRejectsUDP443BeforeDialing(t *testing.T) {
	dials, err := processWithFlow(t, vless.XRV, net.UDPDestination(net.ParseAddress("1.1.1.1"), 443))
	if err == nil {
		t.Fatal("UDP/443 through vision is not rejected")
	}
	if dials != 0 {
		t.Fatalf("UDP/443 through vision dialed the server %d times before it was rejected", dials)
	}
}

func TestDialsWhatVisionDoesNotReject(t *testing.T) {
	for _, c := range []struct {
		name   string
		flow   string
		target net.Destination
	}{
		{"udp443 flow", vless.XRV + "-udp443", net.UDPDestination(net.ParseAddress("1.1.1.1"), 443)},
		{"no flow", "", net.UDPDestination(net.ParseAddress("1.1.1.1"), 443)},
		{"other udp port", vless.XRV, net.UDPDestination(net.ParseAddress("1.1.1.1"), 53)},
		{"tcp 443", vless.XRV, net.TCPDestination(net.ParseAddress("1.1.1.1"), 443)},
	} {
		t.Run(c.name, func(t *testing.T) {
			if dials, _ := processWithFlow(t, c.flow, c.target); dials == 0 {
				t.Fatal("the server is not dialed")
			}
		})
	}
}
