package conf

import (
	"github.com/xtls/xray-core/app/pprof"
)

type PprofConfig struct {
	Tag string `json:"tag"`
}

func (c *PprofConfig) Build() (*pprof.Config, error) {
	if c.Tag == "" {
		return nil, newError("pprof tag can't be empty.")
	}

	return &pprof.Config{
		Tag: c.Tag,
	}, nil
}
