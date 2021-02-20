package conf

import "github.com/xtls/xray-core/app/web/config"

type WebConfig struct {
	Tag   string     `json:"tag"`
	Api   *ApiConfig `json:"api"`
	Pprof bool       `json:"pprof"`
}

type ApiConfig struct {
	Address string `json:"address"`
	Port    uint32 `json:"port"`
}

func (c *WebConfig) Build() (*config.Config, error) {
	if c.Tag == "" {
		return nil, newError("Web tag can't be empty.")
	}

	return &config.Config{
		Tag: c.Tag,
		Api: &config.Api{
			Address: c.Api.Address,
			Port:    c.Api.Port,
		},
		Pprof: c.Pprof,
	}, nil
}
