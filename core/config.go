package core

import (
	"io"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/cmdarg"
	"github.com/xtls/xray-core/main/confloader"
	"google.golang.org/protobuf/proto"
)

// ConfigFormat is a configurable format of Xray config file.
type ConfigFormat struct {
	Name      string
	Extension []string
	Loader    ConfigLoader
}

// ConfigLoader is a utility to load Xray config from external source.
type ConfigLoader func(input interface{}) (*Config, error)

// ConfigBuilder is a builder to build core.Config from filenames and formats
type ConfigBuilder func(files []string, formats []string) (*Config, error)

var (
	configLoaderByName    = make(map[string]*ConfigFormat)
	configLoaderByExt     = make(map[string]*ConfigFormat)
	ConfigBuilderForFiles ConfigBuilder
)

// RegisterConfigLoader add a new ConfigLoader.
func RegisterConfigLoader(format *ConfigFormat) error {
	name := strings.ToLower(format.Name)
	if _, found := configLoaderByName[name]; found {
		return newError(format.Name, " already registered.")
	}
	configLoaderByName[name] = format

	for _, ext := range format.Extension {
		lext := strings.ToLower(ext)
		if f, found := configLoaderByExt[lext]; found {
			return newError(ext, " already registered to ", f.Name)
		}
		configLoaderByExt[lext] = format
	}

	return nil
}

func GetFormatByExtension(ext string) string {
	switch strings.ToLower(ext) {
	case "pb", "protobuf":
		return "protobuf"
	case "yaml", "yml":
		return "yaml"
	case "toml":
		return "toml"
	case "json", "jsonc":
		return "json"
	default:
		return ""
	}
}

func getExtension(filename string) string {
	idx := strings.LastIndexByte(filename, '.')
	if idx == -1 {
		return ""
	}
	return filename[idx+1:]
}

func getFormat(filename string) string {
	return GetFormatByExtension(getExtension(filename))
}

func LoadConfig(formatName string, input interface{}) (*Config, error) {
	switch v := input.(type) {
	case cmdarg.Arg:
		formats := make([]string, len(v))
		hasProtobuf := false
		for i, file := range v {
			var f string

			if formatName == "auto" {
				if file != "stdin:" {
					f = getFormat(file)
				} else {
					f = "json"
				}
			} else {
				f = formatName
			}

			if f == "" {
				return nil, newError("Failed to get format of ", file).AtWarning()
			}

			if f == "protobuf" {
				hasProtobuf = true
			}
			formats[i] = f
		}

		// only one protobuf config file is allowed
		if hasProtobuf {
			if len(v) == 1 {
				return configLoaderByName["protobuf"].Loader(v)
			} else {
				return nil, newError("Only one protobuf config file is allowed").AtWarning()
			}
		}

		// to avoid import cycle
		return ConfigBuilderForFiles(v, formats)

	case io.Reader:
		if f, found := configLoaderByName[formatName]; found {
			return f.Loader(v)
		} else {
			return nil, newError("Unable to load config in", formatName).AtWarning()
		}
	}

	return nil, newError("Unable to load config").AtWarning()
}

func loadProtobufConfig(data []byte) (*Config, error) {
	config := new(Config)
	if err := proto.Unmarshal(data, config); err != nil {
		return nil, err
	}
	return config, nil
}

func init() {
	common.Must(RegisterConfigLoader(&ConfigFormat{
		Name:      "Protobuf",
		Extension: []string{"pb"},
		Loader: func(input interface{}) (*Config, error) {
			switch v := input.(type) {
			case cmdarg.Arg:
				r, err := confloader.LoadConfig(v[0])
				common.Must(err)
				data, err := buf.ReadAllToBytes(r)
				common.Must(err)
				return loadProtobufConfig(data)
			case io.Reader:
				data, err := buf.ReadAllToBytes(v)
				common.Must(err)
				return loadProtobufConfig(data)
			default:
				return nil, newError("unknow type")
			}
		},
	}))
}
