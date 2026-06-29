package tun

import "errors"

var (
	ErrDrop   = errors.New("drop by rule")
	ErrReset  = errors.New("reset by rule")
	ErrBypass = errors.New("bypass by rule")
)
