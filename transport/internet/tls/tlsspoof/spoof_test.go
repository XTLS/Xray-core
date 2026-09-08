package tlsspoof

import (
	"testing"
)

func TestBuildFakeClientHello(t *testing.T) {
	hello, err := buildFakeClientHello("www.example.com")
	if err != nil {
		t.Fatal("buildFakeClientHello returned error:", err)
	}
	if len(hello) == 0 {
		t.Fatal("buildFakeClientHello returned empty payload")
	}
	// TLS record header: content type 0x16 (handshake)
	if hello[0] != 0x16 {
		t.Fatalf("expected TLS handshake record type 0x16, got 0x%02x", hello[0])
	}
	// TLS version: 0x0301 (TLS 1.0 record layer)
	if hello[1] != 0x03 || hello[2] != 0x01 {
		t.Fatalf("unexpected TLS record version: 0x%02x%02x", hello[1], hello[2])
	}
	t.Logf("ClientHello payload length: %d bytes", len(hello))
}

func TestBuildFakeClientHelloEmptySNI(t *testing.T) {
	_, err := buildFakeClientHello("")
	if err == nil {
		t.Fatal("expected error for empty SNI")
	}
}

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

func TestParseOptions(t *testing.T) {
	// Empty spoof should be a no-op
	sni, _, err := ParseOptions("", "")
	if err != nil {
		t.Fatal("ParseOptions(\"\", \"\"): unexpected error:", err)
	}
	if sni != "" {
		t.Fatalf("expected empty SNI, got %q", sni)
	}

	// spoof_method without spoof should error
	_, _, err = ParseOptions("", "wrong-checksum")
	if err == nil {
		t.Fatal("expected error when spoof_method set without spoof")
	}

	// Valid combo
	sni, method, err := ParseOptions("fake.example.com", "wrong-checksum")
	if err != nil {
		t.Fatal("ParseOptions: unexpected error:", err)
	}
	if sni != "fake.example.com" {
		t.Fatalf("expected SNI 'fake.example.com', got %q", sni)
	}
	if method != MethodWrongChecksum {
		t.Fatalf("expected MethodWrongChecksum, got %v", method)
	}

	// IP-literal should be rejected
	_, _, err = ParseOptions("1.2.3.4", "wrong-checksum")
	if err == nil {
		t.Fatal("expected error for IP-literal spoof")
	}
	_, _, err = ParseOptions("::1", "wrong-checksum")
	if err == nil {
		t.Fatal("expected error for IP-literal spoof")
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
