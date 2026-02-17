package mux_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func BenchmarkMuxThroughput(b *testing.B) {
	serverCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	muxServerUplink, muxServerDownlink := newLinkPair()
	dispatcher := TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			inputReader, inputWriter := pipe.New(pipe.WithSizeLimit(512 * 1024))
			outputReader, outputWriter := pipe.New(pipe.WithSizeLimit(512 * 1024))
			go func() {
				defer outputWriter.Close()
				for {
					mb, err := inputReader.ReadMultiBuffer()
					if err != nil {
						break
					}
					buf.ReleaseMulti(mb)
				}
			}()
			return &transport.Link{
				Reader: outputReader,
				Writer: inputWriter,
			}, nil
		},
	}
	_, err := mux.NewServerWorker(serverCtx, &dispatcher, muxServerUplink)
	common.Must(err)
	client, err := mux.NewClientWorker(*muxServerDownlink, mux.ClientStrategy{})
	common.Must(err)
	clientCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("www.example.com"), 80),
	}})
	muxClientUplink, muxClientDownlink := newLinkPair()
	go func() {
		for {
			mb, err := muxClientDownlink.Reader.ReadMultiBuffer()
			if err != nil {
				break
			}
			buf.ReleaseMulti(mb)
		}
	}()
	ok := client.Dispatch(clientCtx, muxClientUplink)
	if !ok {
		b.Fatal("failed to dispatch")
	}
	data := buf.FromBytes(make([]byte, 8192))
	b.SetBytes(int64(8192))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := muxClientUplink.Writer.WriteMultiBuffer(buf.MultiBuffer{data})
		if err != nil {
			b.Fatal(err)
		}
	}
}
