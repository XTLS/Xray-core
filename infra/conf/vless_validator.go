package conf

import (
	"encoding/json"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/vless/validator/memory"
	"github.com/xtls/xray-core/proxy/vless/validator/redis"
	"github.com/xtls/xray-core/proxy/vless/validator/rest"
	"google.golang.org/protobuf/proto"
)

// VLessValidatorConfig selects the vless.Validator backend for a VLESS
// inbound. Type is one of "memory" (default), "redis", or "rest"; Settings
// is backend-specific, see VLessRedisValidatorConfig / VLessRESTValidatorConfig.
//
//	"validator": { "type": "rest", "settings": { "address": "http://user-store:8080" } }
type VLessValidatorConfig struct {
	Type     string           `json:"type"`
	Settings *json.RawMessage `json:"settings"`
}

var vlessValidatorConfigLoader = NewJSONConfigLoader(ConfigCreatorCache{
	"memory": func() interface{} { return new(VLessMemoryValidatorConfig) },
	"redis":  func() interface{} { return new(VLessRedisValidatorConfig) },
	"rest":   func() interface{} { return new(VLessRESTValidatorConfig) },
}, "type", "settings")

type VLessMemoryValidatorConfig struct{}

func (*VLessMemoryValidatorConfig) Build() (proto.Message, error) {
	return &memory.Config{}, nil
}

func (c *VLessValidatorConfig) Build() (proto.Message, error) {
	if c == nil || c.Type == "" {
		return (&VLessMemoryValidatorConfig{}).Build()
	}

	settings := []byte("{}")
	if c.Settings != nil {
		settings = []byte(*c.Settings)
	}

	rawConfig, err := vlessValidatorConfigLoader.LoadWithID(settings, c.Type)
	if err != nil {
		return nil, errors.New("failed to parse VLESS validator config").Base(err)
	}

	return rawConfig.(Buildable).Build()
}

// VLessRedisValidatorConfig configures the Redis-backed validator. Address
// accepts "host:port" or a "redis://[user:pass@]host:port[/db]" /
// "rediss://..." URL; see proxy/vless/validator/redis for the exact format.
type VLessRedisValidatorConfig struct {
	Address string `json:"address"`
}

func (c *VLessRedisValidatorConfig) Build() (proto.Message, error) {
	return &redis.Config{
		Address: c.Address,
	}, nil
}

// VLessRESTValidatorConfig configures the REST-backed validator. Address is
// the base URL of the backend, e.g. "http://user-store:8080"; see
// proxy/vless/validator/rest/rest.yaml for the API contract.
type VLessRESTValidatorConfig struct {
	Address string `json:"address"`
}

func (c *VLessRESTValidatorConfig) Build() (proto.Message, error) {
	return &rest.Config{
		Address: c.Address,
	}, nil
}
