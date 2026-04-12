package custom

import (
	"bytes"
	"testing"
)

func TestEvaluatorSaveAndReuseWithinPacket(t *testing.T) {
	items := []*UDPItem{
		{
			Rand:    4,
			RandMin: 0x2A,
			RandMax: 0x2A,
			Save:    "txid",
		},
		{
			Var: "txid",
		},
	}

	got, err := evaluateUDPItems(items)
	if err != nil {
		t.Fatal(err)
	}

	want := bytes.Repeat([]byte{0x2A}, 8)
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected output: %x", got)
	}
}

func TestEvaluatorSliceReturnsWindow(t *testing.T) {
	sequence := &TCPSequence{
		Sequence: []*TCPItem{
			{
				Expr: &Expr{
					Op: "slice",
					Args: []*ExprArg{
						{Value: &ExprArg_Bytes{Bytes: []byte{1, 2, 3, 4}}},
						{Value: &ExprArg_U64{U64: 1}},
						{Value: &ExprArg_U64{U64: 2}},
					},
				},
			},
		},
	}

	got, err := evaluateTCPSequence(sequence)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, []byte{2, 3}) {
		t.Fatalf("unexpected output: %x", got)
	}
}

func TestEvaluatorConcatPreservesOrder(t *testing.T) {
	items := []*UDPItem{
		{
			Expr: &Expr{
				Op: "concat",
				Args: []*ExprArg{
					{Value: &ExprArg_Bytes{Bytes: []byte("ab")}},
					{Value: &ExprArg_Bytes{Bytes: []byte("cd")}},
					{Value: &ExprArg_Bytes{Bytes: []byte("ef")}},
				},
			},
		},
	}

	got, err := evaluateUDPItems(items)
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != "abcdef" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestEvaluatorBeXorProducesExpectedBytes(t *testing.T) {
	items := []*UDPItem{
		{
			Expr: &Expr{
				Op: "be16",
				Args: []*ExprArg{
					{
						Value: &ExprArg_Expr{
							Expr: &Expr{
								Op: "xor16",
								Args: []*ExprArg{
									{Value: &ExprArg_U64{U64: 0x1234}},
									{Value: &ExprArg_U64{U64: 0xFFFF}},
								},
							},
						},
					},
				},
			},
		},
	}

	got, err := evaluateUDPItems(items)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, []byte{0xED, 0xCB}) {
		t.Fatalf("unexpected output: %x", got)
	}
}

func TestEvaluatorRejectsInvalidArgType(t *testing.T) {
	items := []*UDPItem{
		{
			Expr: &Expr{
				Op: "be16",
				Args: []*ExprArg{
					{Value: &ExprArg_Bytes{Bytes: []byte{0x01}}},
				},
			},
		},
	}

	_, err := evaluateUDPItems(items)
	if err == nil {
		t.Fatal("expected evaluator error")
	}
}
