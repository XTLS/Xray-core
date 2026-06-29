//go:build integration

package tun

import (
	"os"
	"testing"
)

func TestTUN_SystemStack_Integration(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root for TUN")
	}

	s, err := NewSystem(SystemStackOptions{})
	if err != nil {
		t.Fatalf("NewSystem failed: %v", err)
	}
	if s == nil {
		t.Fatal("NewSystem returned nil")
	}
}
