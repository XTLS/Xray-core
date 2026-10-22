package dispatcher

import (
	"context"
	"crypto/tls"
	"io"
	gonet "net"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

const xrayKey core.XrayKey = 1

type multiBufferQueue []buf.MultiBuffer

func (q *multiBufferQueue) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if len(*q) == 0 {
		return nil, io.EOF
	}
	mb := (*q)[0]
	*q = (*q)[1:]
	return mb, nil
}

func bufferOf(b []byte) *buf.Buffer {
	buffer := buf.New()
	buffer.Write(b)
	return buffer
}

func TestSnifferSkipsEmptyRead(t *testing.T) {
	client, server := gonet.Pipe()
	defer client.Close()
	defer server.Close()
	go tls.Client(client, &tls.Config{ServerName: "example.com"}).Handshake()
	hello := make([]byte, 4096)
	n, err := server.Read(hello)
	common.Must(err)

	reader := &multiBufferQueue{{bufferOf(hello[:n/2])}, nil, {bufferOf(hello[n/2 : n])}}
	v, err := core.New(&core.Config{})
	common.Must(err)
	ctx := context.WithValue(context.Background(), xrayKey, v)
	result, err := sniffer(ctx, &cachedReader{reader: &buf.TimeoutWrapperReader{Reader: reader}}, false, net.Network_TCP)
	if err != nil {
		t.Fatal(err)
	}
	if result.Domain() != "example.com" {
		t.Error("expect domain example.com but got ", result.Domain())
	}
}
