package browser_dialer

import (
	"net"
	"strconv"
	"testing"
)

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

func TestEnsureDialerWithAddressReusesSameListenAddress(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	addr1 := net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "/123e4567-e89b-12d3-a456-426614174000"
	addr2 := net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "/123e4567-e89b-12d3-a456-426614174001"
	if err := EnsureDialerWithAddress(addr1); err != nil {
		t.Fatalf("failed to ensure first browser dialer: %v", err)
	}
	if err := EnsureDialerWithAddress(addr2); err != nil {
		t.Fatalf("failed to reuse browser dialer listener on same address: %v", err)
	}
}

func TestEnsureDialerWithAddressRejectsSamePortDifferentAddress(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	addr1 := net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "/123e4567-e89b-12d3-a456-426614174010"
	addr2 := net.JoinHostPort("127.0.0.2", strconv.Itoa(port)) + "/123e4567-e89b-12d3-a456-426614174011"
	if err := EnsureDialerWithAddress(addr1); err != nil {
		t.Fatalf("failed to ensure first browser dialer: %v", err)
	}
	if err := EnsureDialerWithAddress(addr2); err == nil {
		t.Fatal("expected error for same port with different listen address")
	}
}
