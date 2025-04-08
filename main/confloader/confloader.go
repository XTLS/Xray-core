package confloader

import (
	"context"
	"io"
	"os"

	"github.com/hosemorinho412/xray-core/common/errors"
)

type (
	configFileLoader func(string) (io.Reader, error)
	extconfigLoader  func([]string, io.Reader) (io.Reader, error)
)

var (
	EffectiveConfigFileLoader configFileLoader
	EffectiveExtConfigLoader  extconfigLoader
)

// LoadConfig reads from a path/url/stdin
// actual work is in external module
func LoadConfig(file string) (io.Reader, error) {
	if EffectiveConfigFileLoader == nil {
		errors.LogInfo(context.Background(), "external config module not loaded, reading from stdin")
		return os.Stdin, nil
	}
	return EffectiveConfigFileLoader(file)
}

// LoadExtConfig calls xctl to handle multiple config
// the actual work also in external module
func LoadExtConfig(files []string, reader io.Reader) (io.Reader, error) {
	if EffectiveExtConfigLoader == nil {
		return nil, errors.New("external config module not loaded").AtError()
	}

	return EffectiveExtConfigLoader(files, reader)
}
