package mux_test

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

// readOneFrame reads a single mux frame metadata from the reader, draining
// the data chunk if the frame carries one.
func readOneFrame(reader *buf.BufferedReader) (*mux.FrameMetadata, error) {
	var meta mux.FrameMetadata
	if err := meta.Unmarshal(reader, false); err != nil {
		return nil, err
	}
	if meta.Option.Has(mux.OptionData) {
		if err := buf.Copy(mux.NewStreamReader(reader), buf.Discard); err != nil {
			return nil, err
		}
	}
	return &meta, nil
}

// openSession sends a SessionStatusNew frame (no data) for the given session
// ID over the writer, emulating a client opening a mux session.
func openSession(t *testing.T, writer buf.Writer, id uint16) {
	t.Helper()
	dest := net.TCPDestination(net.DomainAddress("www.example.com"), 80)
	sessionWriter := mux.NewWriter(id, dest, writer, protocol.TransferTypeStream, [8]byte{}, nil)
	common.Must(sessionWriter.WriteMultiBuffer(buf.MultiBuffer{}))
}

func setKeepAliveInterval(t *testing.T, interval time.Duration) {
	t.Helper()
	original := mux.ServerKeepAliveInterval
	mux.ServerKeepAliveInterval = interval
	t.Cleanup(func() {
		mux.ServerKeepAliveInterval = original
	})
}

func TestServerSendsKeepAliveWhenIdle(t *testing.T) {
	setKeepAliveInterval(t, 50*time.Millisecond)

	websiteUplink, websiteDownlink := newLinkPair()
	dispatcher := TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			return websiteDownlink, nil
		},
	}
	defer common.Interrupt(websiteUplink.Reader)

	muxServerUplink, muxServerDownlink := newLinkPair()
	worker, err := mux.NewServerWorker(context.Background(), &dispatcher, muxServerUplink)
	common.Must(err)
	defer worker.Close()

	// Open a session and keep it idle: no data in either direction.
	openSession(t, muxServerDownlink.Writer, 1)

	frames := make(chan *mux.FrameMetadata, 16)
	go func() {
		reader := &buf.BufferedReader{Reader: muxServerDownlink.Reader}
		for {
			meta, err := readOneFrame(reader)
			if err != nil {
				close(frames)
				return
			}
			frames <- meta
		}
	}()

	// The downlink is idle while a session is active: the server must emit
	// keepalive frames. Expect at least two to confirm periodic emission.
	for i := 0; i < 2; i++ {
		select {
		case meta, ok := <-frames:
			if !ok {
				t.Fatal("downlink closed before keepalive was received")
			}
			if meta.SessionStatus != mux.SessionStatusKeepAlive {
				t.Fatalf("frame %d: expected status KeepAlive (0x04), got 0x%02x", i, byte(meta.SessionStatus))
			}
			if meta.Option != 0 {
				t.Fatalf("frame %d: keepalive frame must carry no options, got 0x%02x", i, byte(meta.Option))
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("no keepalive frame received within 2s (got %d so far)", i)
		}
	}
}

func TestServerNoKeepAliveWhileDownlinkActive(t *testing.T) {
	setKeepAliveInterval(t, 150*time.Millisecond)

	websiteUplink, websiteDownlink := newLinkPair()
	dispatcher := TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			return websiteDownlink, nil
		},
	}

	muxServerUplink, muxServerDownlink := newLinkPair()
	worker, err := mux.NewServerWorker(context.Background(), &dispatcher, muxServerUplink)
	common.Must(err)
	defer worker.Close()

	openSession(t, muxServerDownlink.Writer, 1)

	type result struct {
		keepAlives int
		frames     int
	}
	done := make(chan result, 1)
	go func() {
		reader := &buf.BufferedReader{Reader: muxServerDownlink.Reader}
		var r result
		for {
			meta, err := readOneFrame(reader)
			if err != nil {
				done <- r
				return
			}
			r.frames++
			if meta.SessionStatus == mux.SessionStatusKeepAlive {
				r.keepAlives++
			}
		}
	}()

	// Keep the downlink busy for three keepalive intervals.
	for i := 0; i < 18; i++ {
		b := buf.New()
		b.WriteString("data")
		common.Must(websiteUplink.Writer.WriteMultiBuffer(buf.MultiBuffer{b}))
		time.Sleep(25 * time.Millisecond)
	}

	// Tear down promptly, before an idle period elapses.
	common.Must(worker.Close())

	select {
	case r := <-done:
		if r.frames == 0 {
			t.Error("expected data frames on the downlink, got none")
		}
		if r.keepAlives != 0 {
			t.Errorf("expected no keepalive frames while downlink is active, got %d (of %d frames)", r.keepAlives, r.frames)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("frame reader did not finish")
	}
}

// TestClientTransparentToKeepAlive verifies backward compatibility: an
// unmodified ClientWorker silently discards the server's keepalive frames
// and continues to deliver data intact.
func TestClientTransparentToKeepAlive(t *testing.T) {
	setKeepAliveInterval(t, 40*time.Millisecond)

	websiteUplink, websiteDownlink := newLinkPair()
	dispatcher := TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			return websiteDownlink, nil
		},
	}

	muxServerUplink, muxServerDownlink := newLinkPair()
	worker, err := mux.NewServerWorker(context.Background(), &dispatcher, muxServerUplink)
	common.Must(err)
	defer worker.Close()

	client, err := mux.NewClientWorker(*muxServerDownlink, mux.ClientStrategy{})
	common.Must(err)

	clientCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("www.example.com"), 80),
	}})

	muxClientUplink, muxClientDownlink := newLinkPair()
	if !client.Dispatch(clientCtx, muxClientUplink) {
		t.Fatal("failed to dispatch")
	}

	{
		b := buf.New()
		b.WriteString("hello")
		common.Must(muxClientDownlink.Writer.WriteMultiBuffer(buf.MultiBuffer{b}))
	}

	resMb, err := websiteUplink.Reader.ReadMultiBuffer()
	common.Must(err)
	if res := resMb.String(); res != "hello" {
		t.Fatal("upload: ", res)
	}

	// Let several keepalive frames cross the wire while the download
	// direction is idle.
	time.Sleep(250 * time.Millisecond)

	if client.Closed() {
		t.Fatal("client closed after receiving keepalive frames")
	}

	{
		b := buf.New()
		b.WriteString("world")
		common.Must(websiteUplink.Writer.WriteMultiBuffer(buf.MultiBuffer{b}))
	}

	readDone := make(chan string, 1)
	go func() {
		resMb, err := muxClientDownlink.Reader.ReadMultiBuffer()
		if err != nil {
			readDone <- "error: " + err.Error()
			return
		}
		readDone <- resMb.String()
	}()

	select {
	case res := <-readDone:
		if res != "world" {
			t.Fatal("download after keepalives: ", res)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("download did not arrive after keepalive frames")
	}
}
