package platform

import (
	"errors"
	"os"
	"sync"
)

var envReloadRegistry = struct {
	sync.RWMutex
	handlers []func() error
}{}

// RegisterEnvReload registers an environment reload handler and runs it once
// immediately so package defaults keep the same behavior as init-time reads.
func RegisterEnvReload(handler func() error) {
	if handler == nil {
		return
	}
	envReloadRegistry.Lock()
	envReloadRegistry.handlers = append(envReloadRegistry.handlers, handler)
	envReloadRegistry.Unlock()
	if err := handler(); err != nil {
		panic(err)
	}
}

// ReloadEnvSettings refreshes all registered environment-backed package state.
func ReloadEnvSettings() error {
	envReloadRegistry.RLock()
	handlers := append([]func() error{}, envReloadRegistry.handlers...)
	envReloadRegistry.RUnlock()

	var errs []error
	for _, handler := range handlers {
		if err := handler(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

type EnvSetting struct {
	Key   string
	Value string
}

type envValue struct {
	value  string
	exists bool
}

var configEnvKeys = map[string]struct{}{
	AssetLocation:        {},
	CertLocation:         {},
	UseReadV:             {},
	UseFreedomSplice:     {},
	UseVmessPadding:      {},
	UseCone:              {},
	BufferSize:           {},
	BrowserDialerAddress: {},
	XUDPLog:              {},
	XUDPBaseKey:          {},
	TunFdKey:             {},
}

// ApplyConfigEnvSettings applies the subset of environment settings that may be
// declared inside an already parsed Xray config. Pre-load keys such as
// xray.json.strict, xray.location.config and xray.location.confdir are
// intentionally excluded.
func ApplyConfigEnvSettings(settings []EnvSetting) (func() error, error) {
	originals := map[string]envValue{}
	for _, setting := range settings {
		if setting.Value == "" {
			continue
		}
		if _, ok := configEnvKeys[setting.Key]; !ok {
			continue
		}
		if _, ok := originals[setting.Key]; !ok {
			value, exists := os.LookupEnv(setting.Key)
			originals[setting.Key] = envValue{
				value:  value,
				exists: exists,
			}
		}
		if err := os.Setenv(setting.Key, setting.Value); err != nil {
			return nil, errors.Join(err, rollbackConfigEnvSettings(originals))
		}
	}
	if len(originals) == 0 {
		return nil, nil
	}
	return func() error {
		return rollbackConfigEnvSettings(originals)
	}, nil
}

func rollbackConfigEnvSettings(originals map[string]envValue) error {
	var errs []error
	for key, original := range originals {
		var err error
		if original.exists {
			err = os.Setenv(key, original.value)
		} else {
			err = os.Unsetenv(key)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
