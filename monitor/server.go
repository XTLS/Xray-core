package monitor

import (
	"github.com/amirdlt/flex"
	. "github.com/amirdlt/flex/util"
)

var (
	s = flex.New(M{}, func(bi *flex.BasicInjector) *I {
		return &I{BasicInjector: bi}
	})
)

func init() {
	go func() {
		s.LogError(s.Run("0.0.0.0:6171"))
	}()
}

func S() *flex.Server[*I] {
	return s
}
