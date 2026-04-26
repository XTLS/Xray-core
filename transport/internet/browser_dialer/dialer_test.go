package browser_dialer

import "testing"

func TestParseBrowserDialerAddressRequireUUIDPath(t *testing.T) {
	valid := "127.0.0.1:8080/123e4567-e89b-12d3-a456-426614174000"
	if _, _, ok := parseBrowserDialerAddress(valid); !ok {
		t.Fatalf("expected valid browser dialer address: %s", valid)
	}

	invalid := []string{
		"127.0.0.1:8080/example",
		"127.0.0.1:8080/short",
		"127.0.0.1:8080/123e4567e89b12d3a456426614174000",
		"127.0.0.1:8080/123e4567-e89b-12d3-a456-426614174000/extra",
	}
	for _, addr := range invalid {
		if _, _, ok := parseBrowserDialerAddress(addr); ok {
			t.Fatalf("expected invalid browser dialer address: %s", addr)
		}
	}
}
