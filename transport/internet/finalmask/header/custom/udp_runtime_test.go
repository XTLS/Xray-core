package custom

import (
	"bytes"
	"net"
	"testing"
)

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

func TestDSLUDPClientWriteSupportsExtendedExprOps(t *testing.T) {
	conn, err := NewConnClientUDP(&UDPConfig{
		Client: []*UDPItem{
			{
				Expr: &Expr{
					Op: "le16",
					Args: []*ExprArg{
						{
							Value: &ExprArg_Expr{
								Expr: &Expr{
									Op: "add",
									Args: []*ExprArg{
										{Value: &ExprArg_U64{U64: 1}},
										{Value: &ExprArg_U64{U64: 2}},
									},
								},
							},
						},
					},
				},
			},
			{
				Expr: &Expr{
					Op: "pad",
					Args: []*ExprArg{
						{Value: &ExprArg_Bytes{Bytes: []byte{0xAA}}},
						{Value: &ExprArg_U64{U64: 3}},
						{Value: &ExprArg_Bytes{Bytes: []byte{0xBB}}},
					},
				},
			},
			{
				Expr: &Expr{
					Op: "truncate",
					Args: []*ExprArg{
						{Value: &ExprArg_Bytes{Bytes: []byte{1, 2, 3, 4}}},
						{Value: &ExprArg_U64{U64: 2}},
					},
				},
			},
			{
				Expr: &Expr{
					Op: "be16",
					Args: []*ExprArg{
						{
							Value: &ExprArg_Expr{
								Expr: &Expr{
									Op: "or",
									Args: []*ExprArg{
										{
											Value: &ExprArg_Expr{
												Expr: &Expr{
													Op: "shl",
													Args: []*ExprArg{
														{Value: &ExprArg_U64{U64: 1}},
														{Value: &ExprArg_U64{U64: 8}},
													},
												},
											},
										},
										{
											Value: &ExprArg_Expr{
												Expr: &Expr{
													Op: "shr",
													Args: []*ExprArg{
														{Value: &ExprArg_U64{U64: 0x80}},
														{Value: &ExprArg_U64{U64: 7}},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	client := conn.(*udpCustomClientConn)
	buf := make([]byte, client.Size())
	if _, err := client.WriteTo(buf, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}); err != nil {
		t.Fatal(err)
	}

	want := []byte{
		0x03, 0x00,
		0xAA, 0xBB, 0xBB,
		0x01, 0x02,
		0x01, 0x01,
	}
	if !bytes.Equal(buf, want) {
		t.Fatalf("unexpected encoded header: %x", buf)
	}
}
