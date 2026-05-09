package rawpacket

import (
	"testing"
)

func TestParseMethod(t *testing.T) {
	tests := []struct {
		input    string
		expected Method
		hasErr   bool
	}{
		{"", MethodWrongSequence, false},
		{"wrong-sequence", MethodWrongSequence, false},
		{"wrong-checksum", MethodWrongChecksum, false},
		{"wrong-ack", MethodWrongAcknowledgment, false},
		{"wrong-md5", MethodWrongMD5Sig, false},
		{"wrong-timestamp", MethodWrongTimestamp, false},
		{"invalid", 0, true},
	}
	for _, tt := range tests {
		m, err := ParseMethod(tt.input)
		if tt.hasErr {
			if err == nil {
				t.Errorf("ParseMethod(%q): expected error, got nil", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseMethod(%q): unexpected error: %v", tt.input, err)
			continue
		}
		if m != tt.expected {
			t.Errorf("ParseMethod(%q) = %v, want %v", tt.input, m, tt.expected)
		}
	}
}

func TestMethodString(t *testing.T) {
	if MethodWrongSequence.String() != "wrong-sequence" {
		t.Fatalf("unexpected method string: %s", MethodWrongSequence.String())
	}
	if MethodWrongChecksum.String() != "wrong-checksum" {
		t.Fatalf("unexpected method string: %s", MethodWrongChecksum.String())
	}
}
