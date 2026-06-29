package tun

import (
	"context"
	"testing"
)

func TestSystemStack_Compile(t *testing.T) {
	var _ Stack = (*SystemStack)(nil)
}

func TestSystemStack_NewSystem(t *testing.T) {
	opts := SystemStackOptions{
		Context: context.Background(),
		Tun:     nil,
		Handler: nil,
	}
	s, err := NewSystem(opts)
	if err != nil {
		t.Log("NewSystem returned error (expected with nil Tun):", err)
	}
	_ = s
}
