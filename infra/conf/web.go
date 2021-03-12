package conf

import (
	"github.com/xtls/xray-core/app/web/config"
)

type WebConfig struct {
	Tag    string          `json:"tag"`
	Api    *ApiConfig      `json:"api"`
	Pprof  bool            `json:"pprof"`
	Static []*StaticConfig `json:"static"`
}

type ApiConfig struct {
	Address string `json:"address"`
	Port    uint32 `json:"port"`
}

type StaticConfig struct {
	FilePath string `json:"filePath"`
	Uri      string `json:"uri"`
}

func (c *StaticConfig) Build() (*config.Static, error) {
	if c.FilePath == "" {
		return nil, newError("could not serve nil filepath")
	}

	if c.Uri == "" {
		return nil, newError("could not use void as uri")
	}

	return &config.Static{
		FilePath: c.FilePath,
		Uri:      c.Uri,
	}, nil
}

func (c *WebConfig) Build() (*config.Config, error) {
	if c.Tag == "" {
		return nil, newError("Web tag can't be empty.")
	}

	config := &config.Config{
		Tag: c.Tag,
		Api: &config.Api{
			Address: c.Api.Address,
			Port:    c.Api.Port,
		},
		Pprof: c.Pprof,
	}

	for _, static := range c.Static {
		s, err := static.Build()
		if err != nil {
			return nil, newError("failed to build http file server")
		}
		config.Static = append(config.Static, s)
	}

	return config, nil
}
