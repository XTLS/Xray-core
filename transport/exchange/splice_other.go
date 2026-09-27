//go:build !linux

package exchange

import "io"

func spliceTransfer(io.Writer, io.Reader, func(int64), func(int64)) (bool, error) { return false, nil }
