package custom

import "testing"

func TestDSLUDPClientSizeTracksEvaluatedItems(t *testing.T) {
	conn, err := NewConnClientUDP(&UDPConfig{
		Client: []*UDPItem{
			{
				Rand:    2,
				RandMin: 0x2A,
				RandMax: 0x2A,
				Save:    "txid",
			},
			{
				Var: "txid",
			},
			{
				Expr: &Expr{
					Op: "concat",
					Args: []*ExprArg{
						{Value: &ExprArg_Bytes{Bytes: []byte{0xAB}}},
						{Value: &ExprArg_Bytes{Bytes: []byte{0xCD}}},
					},
				},
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if got := conn.(*udpCustomClientConn).Size(); got != 6 {
		t.Fatalf("unexpected header size: got=%d want=6", got)
	}
}

func TestDSLUDPServerMatchCapturesSavedValues(t *testing.T) {
	conn, err := NewConnServerUDP(&UDPConfig{
		Client: []*UDPItem{
			{
				Rand: 2,
				Save: "txid",
			},
			{
				Var: "txid",
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	server := conn.(*udpCustomServerConn)
	if !server.header.Match([]byte{0x01, 0x02, 0x01, 0x02}) {
		t.Fatal("expected packet to match")
	}

	if got := string(server.header.vars["txid"]); got != string([]byte{0x01, 0x02}) {
		t.Fatalf("unexpected saved txid: %x", server.header.vars["txid"])
	}
}

func TestDSLUDPServerRejectsMalformedVarReference(t *testing.T) {
	conn, err := NewConnServerUDP(&UDPConfig{
		Client: []*UDPItem{
			{
				Rand: 2,
				Save: "txid",
			},
			{
				Var: "txid",
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	server := conn.(*udpCustomServerConn)
	if server.header.Match([]byte{0x01, 0x02, 0x03, 0x04}) {
		t.Fatal("expected packet mismatch")
	}
}
