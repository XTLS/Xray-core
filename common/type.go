package common

import (
	"context"
	"reflect"

	"github.com/xtls/xray-core/common/cache"
)

// ConfigCreator is a function to create an object by a config.
type ConfigCreator func(ctx context.Context, config interface{}) (interface{}, error)

var typeCreatorRegistry = make(map[reflect.Type]ConfigCreator)

// RegisterConfig registers a global config creator. The config can be nil but must have a type.
func RegisterConfig(config interface{}, configCreator ConfigCreator) error {
	configType := reflect.TypeOf(config)
	if _, found := typeCreatorRegistry[configType]; found {
		return newError(configType.Name() + " is already registered").AtError()
	}
	typeCreatorRegistry[configType] = configCreator
	return nil
}

var configCache = cache.NewConfigCache()

func RemoveConfig(key interface{}) {
	configCache.Remove(key)
}

func GetConfig(key interface{}) (string, bool) {
	return configCache.Get(key)
}

// CreateObject creates an object by its config. The config type must be registered through RegisterConfig().
func CreateObject(ctx context.Context, config interface{}) (interface{}, error) {
	configType := reflect.TypeOf(config)
	creator, found := typeCreatorRegistry[configType]
	if !found {
		return nil, newError(configType.String() + " is not registered").AtError()
	}

	inst, err := creator(ctx, config)
	if err != nil {
		return nil, err
	}
	configCache.Add(inst, config)
	return inst, nil
}
