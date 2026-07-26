package outbound

import (
	"net"
	"testing"
)

type unsupportedConn struct {
	net.Conn
}

func TestCheckConnType(t *testing.T) {
	err := checkConnType(&unsupportedConn{})
	if err == nil {
		t.Error("expected error for unsupported connection type, got nil")
	}
}

func TestCheckConnTypeNil(t *testing.T) {
	err := checkConnType(nil)
	if err == nil {
		t.Error("expected error for nil connection, got nil")
	}
}
