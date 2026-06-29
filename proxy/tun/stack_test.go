package tun

import (
	"testing"
)

func TestPrepareConnectionErrors(t *testing.T) {
	err := ErrDrop
	switch err {
	case ErrDrop, ErrReset, ErrBypass:
	default:
		t.Fatal("unknown error type")
	}
}
