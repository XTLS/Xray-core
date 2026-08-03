package platform

import (
	"errors"
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
