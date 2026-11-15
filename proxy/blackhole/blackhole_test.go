package blackhole_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestBlackholeHTTPResponse(t *testing.T) {
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	handler, err := blackhole.New(ctx, &blackhole.Config{
		Response: &blackhole.Response{Type: "http"},
	})
	common.Must(err)

	reader, writer := pipe.New(pipe.WithoutSizeLimit())

	dataCh := make(chan buf.MultiBuffer, 1)
	go func() {
		mb := common.Must2(reader.ReadMultiBuffer())
		dataCh <- mb
	}()
	link := transport.Link{
		Reader: reader,
		Writer: writer,
	}
	common.Must(handler.Process(ctx, &link, nil))
	mb := <-dataCh
	data := make([]byte, mb.Len())
	mb.Copy(data)
	resp := common.Must2(http.ReadResponse(bufio.NewReader(bytes.NewBuffer(data)), nil))
	if resp.StatusCode != 403 {
		t.Errorf("expected 403 response, got %d", resp.StatusCode)
	}
}

func TestBlackholeCustomResponse(t *testing.T) {
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	// slightly bigger than a buffer
	expected := make([]byte, buf.Size+1000)
	if _, err := rand.Read(expected); err != nil {
		t.Fatal(err)
	}
	handler, err := blackhole.New(ctx, &blackhole.Config{
		Response: &blackhole.Response{
			Type:               "custom",
			CustomResponseData: expected,
		},
	})
	common.Must(err)

	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	type readResult struct {
		mb  buf.MultiBuffer
		err error
	}
	resultCh := make(chan readResult, 1)
	go func() {
		mb, err := reader.ReadMultiBuffer()
		resultCh <- readResult{mb: mb, err: err}
	}()

	link := transport.Link{Reader: reader, Writer: writer}
	common.Must(handler.Process(ctx, &link, nil))
	result := <-resultCh
	common.Must(result.err)

	if result.mb.String() != string(expected) {
		t.Errorf("custom response mismatch")
	}
}
