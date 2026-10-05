package tls

import (
	"bytes"
	gotls "crypto/tls"
	"io"
	"testing"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/reality"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/proxy/vless/encryption"
)

func TestInput(t *testing.T) {
	// XTLS Vision fails for the connections of the one that renames what it looks into
	for _, conn := range []any{&gotls.Conn{}, &utls.Conn{}, &reality.Conn{}, &encryption.CommonConn{}} {
		if input, rawInput := Input(conn); input == nil || rawInput == nil {
			t.Errorf("unexpected fields in %T", conn)
		}
	}
}

func TestUConnDropHandshakeState(t *testing.T) {
	for _, version := range []uint16{gotls.VersionTLS13, gotls.VersionTLS12} {
		conn, peer := waitPair(t, true, version, nil)
		c := conn.(*UConn)
		spec := utils.TryAccessField[*utls.ClientHelloSpec](c.UConn, "clientHelloSpec")
		hand := utils.TryAccessField[bytes.Buffer](c.Conn, "hand")
		if spec == nil || hand == nil {
			t.Fatal("unexpected fields in uTLS")
		}
		// up to TLS 1.2 a renegotiation needs it
		dropped := c.HandshakeState.Hello == nil && c.Extensions == nil && *spec == nil && hand.Cap() == 0
		if dropped != (version == gotls.VersionTLS13) {
			t.Error("version: ", version, ", handshake state dropped: ", dropped)
		}
		// the session tickets and what follows them are read as before
		data := make([]byte, 20000)
		go peer.Write(data)
		common.Must2(io.ReadFull(conn, data))
		go conn.Write(data)
		common.Must2(io.ReadFull(peer, data))
	}
}
