package conf

import (
	go_errors "errors"
	"net/url"
	"os"

	"github.com/robfig/cron/v3"
	"github.com/xtls/xray-core/app/geodata"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"google.golang.org/protobuf/proto"
)

type GeodataAssetConfig struct {
	URL      string `json:"url"`
	File     string `json:"file"`
	HashURL  string `json:"hashUrl"`
	HashFile string `json:"hashFile"`
	HashType string `json:"hashType"`
}

func (c *GeodataAssetConfig) Build() (*geodata.Asset, error) {
	if err := validateHTTPS(c.URL); err != nil {
		return nil, errors.New("invalid geodata asset url: ", c.URL).Base(err)
	}
	if _, err := filesystem.StatAsset(c.File); err != nil {
		return nil, errors.New("invalid geodata asset file: ", c.File).Base(err)
	}
	asset := &geodata.Asset{
		Url:  c.URL,
		File: c.File,
	}
	if !c.hasHash() {
		return asset, nil
	}
	if c.HashURL == "" || c.HashFile == "" {
		return nil, errors.New("geodata hashUrl and hashFile must be set together")
	}
	if err := validateHTTPS(c.HashURL); err != nil {
		return nil, errors.New("invalid geodata asset hash url: ", c.HashURL).Base(err)
	}
	if c.HashFile == c.File {
		return nil, errors.New("geodata asset hash file must be different from file: ", c.HashFile)
	}
	if err := validateOptionalAssetFile(c.HashFile); err != nil {
		return nil, errors.New("invalid geodata asset hash file: ", c.HashFile).Base(err)
	}
	hashType, err := geodata.NormalizeHashType(c.HashType)
	if err != nil {
		return nil, err
	}
	asset.HashUrl = c.HashURL
	asset.HashFile = c.HashFile
	asset.HashType = hashType

	return asset, nil
}

func (c *GeodataAssetConfig) hasHash() bool {
	return c.HashURL != "" || c.HashFile != "" || c.HashType != ""
}

func validateOptionalAssetFile(file string) error {
	path, err := filesystem.ResolveAssetPath(file)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		if go_errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("asset is not a regular file")
	}
	return nil
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
