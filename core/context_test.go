package core_test

import (
	"context"
	"testing"

	. "github.com/xtls/xray-core/core"
)

func TestContextPanic(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Error("expect panic, but nil")
		}
	}()

	MustFromContext(context.Background())
}
