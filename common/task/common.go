package task

import (
	"context"

	"github.com/xtls/xray-core/common"
)

// Close returns a func() that closes v.
func Close(v interface{}) func() error {
	return func() error {
		return common.Close(v)
	}
}

// CloseContext returns a func(context.Context) that closes v.
func CloseContext(v interface{}) func(context.Context) error {
	return func(context.Context) error {
		return common.Close(v)
	}
}
