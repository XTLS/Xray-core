package multiplex_test

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/vless/multiplex"
)

func TestFrameEndpoints(t *testing.T) {
	target := net.TCPDestination(net.DomainAddress("example.test"), 443)
	src := net.TCPDestination(net.LocalHostIP, 2053)
	local := net.UDPDestination(net.ParseAddress("::1"), 5060)
	// Wire bytes from the codec before consolidating its endpoint decoder.
	const targetBytes = "000701000101bb020c6578616d706c652e74657374"
	const sourceBytes = "010805017f000001"
	const localBytes = "0213c40300000000000000000000000000000001"
	for _, tc := range []struct {
		name, wire string
		input      session.Inbound
	}{
		{"heartbeat", "0015" + targetBytes, session.Inbound{}},
		{"source-only", "001d" + targetBytes + sourceBytes, session.Inbound{Source: src}},
		{"both", "0031" + targetBytes + sourceBytes + localBytes, session.Inbound{Source: src, Local: local}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := multiplex.FrameMetadata{
				Target: target, SessionID: 7, SessionStatus: multiplex.SessionStatusNew, Inbound: &tc.input,
			}
			wire := buf.New()
			defer wire.Release()
			if err := frame.WriteTo(wire); err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(wire.Bytes()); got != tc.wire {
				t.Fatalf("metadata = %s, want %s", got, tc.wire)
			}
			source := io.MultiReader(bytes.NewReader(wire.Bytes()), bytes.NewReader([]byte("payload")))
			reader := &buf.BufferedReader{Reader: buf.NewReader(source)}
			var decoded multiplex.FrameMetadata
			if err := decoded.Unmarshal(reader, true); err != nil {
				t.Fatal(err)
			}
			if decoded.Inbound == nil || decoded.Target != target ||
				decoded.Inbound.Source != tc.input.Source || decoded.Inbound.Local != tc.input.Local {
				t.Fatalf("unexpected endpoint metadata: %+v", decoded)
			}
			if rest, err := io.ReadAll(reader); err != nil || string(rest) != "payload" {
				t.Fatalf("payload was consumed with metadata: %q, err = %v", rest, err)
			}
		})
	}
}

func BenchmarkFrameWrite(b *testing.B) {
	frame := multiplex.FrameMetadata{
		Target:        net.TCPDestination(net.DomainAddress("www.example.com"), net.Port(80)),
		SessionID:     1,
		SessionStatus: multiplex.SessionStatusNew,
	}
	writer := buf.New()
	defer writer.Release()

	for i := 0; i < b.N; i++ {
		common.Must(frame.WriteTo(writer))
		writer.Clear()
	}
}
