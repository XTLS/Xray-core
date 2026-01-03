package xpool_test

import (
	"testing"

	"github.com/xtls/xray-core/common/xpool"
)

func TestFlags(t *testing.T) {
	tests := []struct {
		name          string
		typeVal       xpool.SegmentType
		sidLen        int
		seqLen        int
		payloadLenLen int
	}{
		{"Small Data", xpool.TypeDATA, 0, 2, 2},
		{"Data with SID", xpool.TypeDATA, 2, 2, 2},
		{"Large Data", xpool.TypeDATA, 4, 4, 3},
		{"RST", xpool.TypeRST, 0, 2, 0},
		{"EOF", xpool.TypeEOF, 0, 2, 0},
		{"Probe", xpool.TypePROBE, 0, 4, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			flags := xpool.ConstructFlags(tc.typeVal, tc.sidLen, tc.seqLen, tc.payloadLenLen)

			// Verify Type
			if got := xpool.GetType(flags); got != tc.typeVal {
				t.Errorf("GetType() = %v, want %v", got, tc.typeVal)
			}

			// Verify ParseFlags
			sid, seq, pay := xpool.ParseFlags(flags)
			if sid != tc.sidLen {
				t.Errorf("ParseFlags sidLen = %v, want %v", sid, tc.sidLen)
			}
			if seq != tc.seqLen {
				t.Errorf("ParseFlags seqLen = %v, want %v", seq, tc.seqLen)
			}
			if pay != tc.payloadLenLen {
				t.Errorf("ParseFlags payloadLenLen = %v, want %v", pay, tc.payloadLenLen)
			}
		})
	}
}
