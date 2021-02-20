package conf

import "github.com/xtls/xray-core/app/web/config"

type WebConfig struct {
	Tag     string `json:"tag"`
	Address string `json:"address"`
	Port    uint32 `json:"port"`
	Pprof   bool   `json:"pprof"`
}

func (c *WebConfig) Build() (*config.Config, error) {
	if c.Tag == "" {
		return nil, newError("Web tag can't be empty.")
	}

	return &config.Config{
		Tag:     c.Tag,
		Address: c.Address,
		Port:    c.Port,
		Pprof:   c.Pprof,
	}, nil
}
