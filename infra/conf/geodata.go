package conf

import (
	"net/url"
	"strings"

	"github.com/robfig/cron/v3"
	"github.com/xtls/xray-core/app/geodata"
	"github.com/xtls/xray-core/common/errors"
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
	return &geodata.Asset{
		Url:  migrateGeodataURL(c.URL),
		File: c.File,
	}, nil
}

func migrateGeodataURL(assetURL string) string {
	if strings.HasSuffix(strings.ToLower(assetURL), ".dat") && (strings.HasPrefix(strings.ToLower(assetURL), "https://github.com/xtls/xray-rules-dat/") ||
		strings.HasPrefix(strings.ToLower(assetURL), "https://raw.githubusercontent.com/xtls/xray-rules-dat/")) {
		errors.PrintDeprecatedFeatureWarning(assetURL, assetURL+".gz")
		return assetURL + ".gz"
	}
	return assetURL
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
