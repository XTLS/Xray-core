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

	_ = NewSystem(SystemStackOptions{})
}
