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

func TestEvaluatorLittleEndianProducesExpectedBytes(t *testing.T) {
	items := []*UDPItem{
		{
			Expr: &Expr{
				Op: "concat",
				Args: []*ExprArg{
					{
						Value: &ExprArg_Expr{
							Expr: &Expr{
								Op: "le16",
								Args: []*ExprArg{
									{Value: &ExprArg_U64{U64: 0x1234}},
								},
							},
						},
					},
					{
						Value: &ExprArg_Expr{
							Expr: &Expr{
								Op: "le32",
								Args: []*ExprArg{
									{Value: &ExprArg_U64{U64: 0xA1B2C3D4}},
								},
							},
						},
					},
					{
						Value: &ExprArg_Expr{
							Expr: &Expr{
								Op: "le64",
								Args: []*ExprArg{
									{Value: &ExprArg_U64{U64: 0x0102030405060708}},
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

	want := []byte{
		0x34, 0x12,
		0xD4, 0xC3, 0xB2, 0xA1,
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected output: %x", got)
	}
}

func TestEvaluatorPadAndTruncateShapeBytes(t *testing.T) {
	items := []*UDPItem{
		{
			Expr: &Expr{
				Op: "concat",
				Args: []*ExprArg{
					{
						Value: &ExprArg_Expr{
							Expr: &Expr{
								Op: "pad",
								Args: []*ExprArg{
									{Value: &ExprArg_Bytes{Bytes: []byte{0xAA, 0xBB}}},
									{Value: &ExprArg_U64{U64: 5}},
									{Value: &ExprArg_Bytes{Bytes: []byte{0xCC, 0xDD}}},
								},
							},
						},
					},
					{
						Value: &ExprArg_Expr{
							Expr: &Expr{
								Op: "truncate",
								Args: []*ExprArg{
									{Value: &ExprArg_Bytes{Bytes: []byte{1, 2, 3, 4}}},
									{Value: &ExprArg_U64{U64: 2}},
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

	want := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xCC, 0x01, 0x02}
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected output: %x", got)
	}
}

func TestMeasureUDPItemsSupportsPadAndTruncate(t *testing.T) {
	items := []*UDPItem{
		{
			Expr: &Expr{
				Op: "pad",
				Args: []*ExprArg{
					{Value: &ExprArg_Bytes{Bytes: []byte{0xAA}}},
					{Value: &ExprArg_U64{U64: 4}},
					{Value: &ExprArg_Bytes{Bytes: []byte{0x00}}},
				},
			},
		},
		{
			Expr: &Expr{
				Op: "truncate",
				Args: []*ExprArg{
					{Value: &ExprArg_Bytes{Bytes: []byte{1, 2, 3, 4}}},
					{Value: &ExprArg_U64{U64: 3}},
				},
			},
		},
	}

	got, err := measureUDPItems(items)
	if err != nil {
		t.Fatal(err)
	}

	if got != 7 {
		t.Fatalf("unexpected size: %d", got)
	}
}

func TestEvaluatorArithmeticAndBitwiseProduceExpectedBytes(t *testing.T) {
	items := []*UDPItem{
		{
			Expr: &Expr{
				Op: "concat",
				Args: []*ExprArg{
					{
						Value: &ExprArg_Expr{
							Expr: &Expr{
								Op: "be16",
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
					},
					{
						Value: &ExprArg_Expr{
							Expr: &Expr{
								Op: "be16",
								Args: []*ExprArg{
									{
										Value: &ExprArg_Expr{
											Expr: &Expr{
												Op: "sub",
												Args: []*ExprArg{
													{Value: &ExprArg_U64{U64: 10}},
													{Value: &ExprArg_U64{U64: 3}},
												},
											},
										},
									},
								},
							},
						},
					},
					{
						Value: &ExprArg_Expr{
							Expr: &Expr{
								Op: "be16",
								Args: []*ExprArg{
									{
										Value: &ExprArg_Expr{
											Expr: &Expr{
												Op: "and",
												Args: []*ExprArg{
													{Value: &ExprArg_U64{U64: 0xF0F0}},
													{Value: &ExprArg_U64{U64: 0x0FF0}},
												},
											},
										},
									},
								},
							},
						},
					},
					{
						Value: &ExprArg_Expr{
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
				},
			},
		},
	}

	got, err := evaluateUDPItems(items)
	if err != nil {
		t.Fatal(err)
	}

	want := []byte{
		0x00, 0x03,
		0x00, 0x07,
		0x00, 0xF0,
		0x01, 0x01,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected output: %x", got)
	}
}

func TestEvaluatorRejectsInvalidShapingAndArithmetic(t *testing.T) {
	tests := []struct {
		name  string
		items []*UDPItem
		match string
	}{
		{
			name: "pad with empty fill",
			items: []*UDPItem{
				{
					Expr: &Expr{
						Op: "pad",
						Args: []*ExprArg{
							{Value: &ExprArg_Bytes{Bytes: []byte{0xAA}}},
							{Value: &ExprArg_U64{U64: 4}},
							{Value: &ExprArg_Bytes{Bytes: []byte{}}},
						},
					},
				},
			},
			match: "pad fill",
		},
		{
			name: "truncate beyond source",
			items: []*UDPItem{
				{
					Expr: &Expr{
						Op: "truncate",
						Args: []*ExprArg{
							{Value: &ExprArg_Bytes{Bytes: []byte{1, 2}}},
							{Value: &ExprArg_U64{U64: 3}},
						},
					},
				},
			},
			match: "truncate",
		},
		{
			name: "sub underflow",
			items: []*UDPItem{
				{
					Expr: &Expr{
						Op: "be16",
						Args: []*ExprArg{
							{
								Value: &ExprArg_Expr{
									Expr: &Expr{
										Op: "sub",
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
			},
			match: "underflow",
		},
		{
			name: "shift too large",
			items: []*UDPItem{
				{
					Expr: &Expr{
						Op: "be16",
						Args: []*ExprArg{
							{
								Value: &ExprArg_Expr{
									Expr: &Expr{
										Op: "shl",
										Args: []*ExprArg{
											{Value: &ExprArg_U64{U64: 1}},
											{Value: &ExprArg_U64{U64: 64}},
										},
									},
								},
							},
						},
					},
				},
			},
			match: "shift",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := evaluateUDPItems(tt.items)
			if err == nil {
				t.Fatal("expected evaluator error")
			}
			if !bytes.Contains([]byte(err.Error()), []byte(tt.match)) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
