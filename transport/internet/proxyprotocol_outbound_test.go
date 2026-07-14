package internet_test

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	. "github.com/xtls/xray-core/transport/internet"
)

type recordingConn struct {
	bytes.Buffer
}

func (c *recordingConn) Read(_ []byte) (int, error)       { return 0, io.EOF }
func (c *recordingConn) Close() error                     { return nil }
func (c *recordingConn) LocalAddr() xnet.Addr             { return nil }
func (c *recordingConn) RemoteAddr() xnet.Addr            { return nil }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

func TestWriteOutboundProxyProtocolV1(t *testing.T) {
	conn := &recordingConn{}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: xnet.TCPDestination(xnet.ParseAddress("1.2.3.4"), 1234),
		Local:  xnet.TCPDestination(xnet.ParseAddress("5.6.7.8"), 443),
	})

	common.Must(WriteOutboundProxyProtocol(ctx, conn, &SocketConfig{SendProxyProtocol: 1}))

	const expected = "PROXY TCP4 1.2.3.4 5.6.7.8 1234 443\r\n"
	if got := conn.String(); got != expected {
		t.Fatal("unexpected proxy protocol header: ", got)
	}
}

func TestWriteOutboundProxyProtocolV2(t *testing.T) {
	conn := &recordingConn{}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: xnet.TCPDestination(xnet.ParseAddress("1.2.3.4"), 1234),
		Local:  xnet.TCPDestination(xnet.ParseAddress("5.6.7.8"), 443),
	})

	common.Must(WriteOutboundProxyProtocol(ctx, conn, &SocketConfig{SendProxyProtocol: 2}))

	expected := []byte{
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
		0x21,
		0x11,
		0x00, 0x0C,
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
		0x04, 0xD2,
		0x01, 0xBB,
	}
	if got := conn.Bytes(); !bytes.Equal(got, expected) {
		t.Fatalf("unexpected proxy protocol v2 header:\n  got: %x\n  want: %x", got, expected)
	}
}

func TestWriteOutboundProxyProtocolWithoutInbound(t *testing.T) {
	conn := &recordingConn{}

	common.Must(WriteOutboundProxyProtocol(context.Background(), conn, &SocketConfig{SendProxyProtocol: 1}))

	if got := conn.Len(); got != 0 {
		t.Fatal("expected no bytes to be written, got ", got)
	}
}
