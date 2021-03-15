package serial

import (
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/main/confloader"
	"io"
)

func BuildConfig(files []string, formats []string) (*core.Config, error) {

	cf := &conf.Config{}
	for i, file := range files {
		newError("Reading config: ", file).AtInfo().WriteToLog()
		r, err := confloader.LoadConfig(file)
		if err != nil {
			return nil, newError("failed to read config: ", file).Base(err)
		}
		c, err := ReaderDecoderByFormat[formats[i]](r)
		if err != nil {
			return nil, newError("failed to decode config: ", file).Base(err)
		}
		if i == 0 {
			*cf = *c
			continue
		}
		cf.Override(c, file)
	}
	return cf.Build()
}

type readerDecoder func(io.Reader) (*conf.Config, error)

var (
	ReaderDecoderByFormat = make(map[string]readerDecoder)
)

func init() {
	ReaderDecoderByFormat["json"] = DecodeJSONConfig
	ReaderDecoderByFormat["yaml"] = DecodeYAMLConfig
	ReaderDecoderByFormat["toml"] = DecodeTOMLConfig

	core.ConfigBuilderForFiles = BuildConfig
}
