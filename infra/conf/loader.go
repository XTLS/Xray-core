package conf

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform"
)

type ConfigCreator func() interface{}

type ConfigCreatorCache map[string]ConfigCreator

func (v ConfigCreatorCache) RegisterCreator(id string, creator ConfigCreator) error {
	if _, found := v[id]; found {
		return errors.New(id, " already registered.").AtError()
	}

	v[id] = creator
	return nil
}

func (v ConfigCreatorCache) CreateConfig(id string) (interface{}, error) {
	creator, found := v[id]
	if !found {
		return nil, errors.New("unknown config id: ", id)
	}
	return creator(), nil
}

type JSONConfigLoader struct {
	cache     ConfigCreatorCache
	idKey     string
	configKey string
}

func NewJSONConfigLoader(cache ConfigCreatorCache, idKey string, configKey string) *JSONConfigLoader {
	return &JSONConfigLoader{
		idKey:     idKey,
		configKey: configKey,
		cache:     cache,
	}
}

func rejectUnknownFields() bool {
	return platform.NewEnvFlag(platform.UseStrictJSON).GetValue(func() string { return "" }) != "false"
}

func (v *JSONConfigLoader) LoadWithID(raw []byte, id string) (interface{}, error) {
	id = strings.ToLower(id)
	config, err := v.cache.CreateConfig(id)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if rejectUnknownFields() {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(config); err != nil {
		return nil, err
	}
	return config, nil
}

func (v *JSONConfigLoader) Load(raw []byte) (interface{}, string, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, "", err
	}
	rawID, found := obj[v.idKey]
	if !found {
		return nil, "", errors.New(v.idKey, " not found in JSON context").AtError()
	}
	var id string
	if err := json.Unmarshal(rawID, &id); err != nil {
		return nil, "", err
	}
	var rawConfig json.RawMessage
	if len(v.configKey) > 0 {
		configValue, found := obj[v.configKey]
		if found {
			rawConfig = configValue
		} else {
			rawConfig = json.RawMessage([]byte("{}"))
		}
	} else {
		// When there's no configKey, the idKey (e.g. "type") is already consumed
		// as routing metadata. Strip it so LoadWithID doesn't reject it as unknown.
		delete(obj, v.idKey)
		cleaned, err := json.Marshal(obj)
		if err != nil {
			return nil, "", err
		}
		rawConfig = cleaned
	}
	config, err := v.LoadWithID([]byte(rawConfig), id)
	if err != nil {
		return nil, id, err
	}
	return config, id, nil
}
