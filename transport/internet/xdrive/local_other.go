//go:build !windows

package xdrive

import (
	"context"
	"os"
)

func readFile(_ context.Context, name string) ([]byte, error) {
	return os.ReadFile(name)
}
