package dns

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type captureDispatcher struct {
	link *transport.Link
	dest net.Destination
}

func (d *captureDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	d.dest = dest
	return d.link, nil
}

func (d *captureDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	return nil
}

func (d *captureDispatcher) Start() error {
	return nil
}

func (d *captureDispatcher) Close() error {
	return nil
}

func (d *captureDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

func TestClassicNameServerSendQueryDoesNotOverridePacketDestination(t *testing.T) {
	uplinkReader, uplinkWriter := pipe.New(pipe.WithSizeLimit(1024))
	downlinkReader, downlinkWriter := pipe.New(pipe.WithSizeLimit(1024))
	defer uplinkReader.Interrupt()
	defer uplinkWriter.Close()
	defer downlinkReader.Interrupt()
	defer downlinkWriter.Close()

	dispatcher := &captureDispatcher{
		link: &transport.Link{
			Reader: downlinkReader,
			Writer: uplinkWriter,
		},
	}
	server := NewClassicNameServer(net.UDPDestination(net.DomainAddress("resolver.test"), 53), dispatcher, false, false, 0, nil)
	defer server.requestsCleanup.Close()
	defer server.udpServer.RemoveRay()

	instance, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)

	server.sendQuery(ctx, nil, "service.test.", dns_feature.IPOption{IPv4Enable: true})

	mb, err := uplinkReader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(mb)

	if len(mb) == 0 {
		t.Fatal("expected DNS query payload")
	}
	if mb[0].UDP != nil {
		t.Fatalf("expected DNS query payload without packet destination override, got %v", mb[0].UDP)
	}
	if dispatcher.dest.String() != "udp:resolver.test:53" {
		t.Fatalf("unexpected dispatch destination: %v", dispatcher.dest)
	}
}
