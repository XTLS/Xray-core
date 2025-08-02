package conf

import (
	"github.com/xtls/xray-core/app/version"
	"github.com/xtls/xray-core/core"
	"strconv"
)

type VersionConfig struct {
	Min string `json:"min"`
	Max string `json:"max"`
}

func (c *VersionConfig) Build() (*version.Config, error) {
	xrayVersion := strconv.Itoa(int(core.Version_x)) + "." + strconv.Itoa(int(core.Version_y)) + "." + strconv.Itoa(int(core.Version_z))

	return &version.Config{
		XrayVersion: xrayVersion,
		MinVersion:  c.Min,
		MaxVersion:  c.Max,
	}, nil
}
