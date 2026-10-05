package tls

import (
	gotls "crypto/tls"
	"testing"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/reality"
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
