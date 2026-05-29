package conf

import (
	"net/url"

	"github.com/robfig/cron/v3"
	"github.com/xtls/xray-core/app/geodata"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"google.golang.org/protobuf/proto"
)

type GeodataAssetConfig struct {
	URL  string `json:"url"`
	File string `json:"file"`
}

func (c *GeodataAssetConfig) Build() (*geodata.Asset, error) {
	if err := validateHTTPS(c.URL); err != nil {
		return nil, errors.New("invalid geodata asset url: ", c.URL).Base(err)
	}
	if _, err := filesystem.StatAsset(c.File); err != nil {
		return nil, errors.New("invalid geodata asset file: ", c.File).Base(err)
	}
	return &geodata.Asset{
		Url:  c.URL,
		File: c.File,
	}, nil
}

func validateHTTPS(s string) error {
	u, err := url.ParseRequestURI(s)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Host == "" {
		return errors.New("scheme must be https")
	}
	return nil
}

type GeodataConfig struct {
	Cron     *string               `json:"cron"`
	Outbound string                `json:"outbound"`
	Assets   []*GeodataAssetConfig `json:"assets"`
}

func (c *GeodataConfig) Build() (proto.Message, error) {
	config := &geodata.Config{}

	if c.Cron != nil {
		if _, err := cron.ParseStandard(*c.Cron); err != nil {
			return nil, errors.New("invalid geodata cron").Base(err)
		}
		config.Cron = *c.Cron
	}

	config.Outbound = c.Outbound

	assets := make([]*geodata.Asset, 0, len(c.Assets))
	for _, asset := range c.Assets {
		built, err := asset.Build()
		if err != nil {
			return nil, err
		}
		assets = append(assets, built)
	}
	config.Assets = assets

	return config, nil
}
