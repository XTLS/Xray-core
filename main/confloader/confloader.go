package confloader

import (
	"io"
	"os"
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
		newError("external config module not loaded, reading from stdin").AtInfo().WriteToLog()
		return os.Stdin, nil
	}
	return EffectiveConfigFileLoader(file)
}

// LoadExtConfig calls xctl to handle multiple config
// the actual work also in external module
func LoadExtConfig(files []string, reader io.Reader) (io.Reader, error) {
	if EffectiveExtConfigLoader == nil {
		return nil, newError("external config module not loaded").AtError()
	}

	return EffectiveExtConfigLoader(files, reader)
}
