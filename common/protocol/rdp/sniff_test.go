package rdp

import (
	"testing"
)

func TestSniffRDP(t *testing.T) {
	tests := []struct {
		input    []byte
		expected *SniffHeader
		wantErr  bool
	}{
		{
			input:    []byte{0x03, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00},
			expected: &SniffHeader{},
			wantErr:  false,
		},
		{
			input:    []byte{0x01, 0x02, 0x03, 0x04},
			expected: nil,
			wantErr:  true,
		},
		{
			input:    []byte{0x03, 0x00, 0x00, 0x13, 0x00, 0x00},
			expected: &SniffHeader{},
			wantErr:  false,
		},
		{
			input:    []byte{0x03, 0x00, 0x00, 0x12},
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got, err := SniffRDP(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("SniffRDP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil && !tt.wantErr && *got != *tt.expected {
				t.Errorf("SniffRDP() = %v, want %v", got, tt.expected)
			}
		})
	}
}
