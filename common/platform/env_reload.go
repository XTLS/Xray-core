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
func ApplyConfigEnvSettings(values map[string]string) error {
	for key, value := range values {
		if value == "" {
			continue
		}
		if _, ok := configEnvKeys[key]; !ok {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return err
		}
	}
	return ReloadEnvSettings()
}
