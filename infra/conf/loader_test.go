package conf_test

import (
	"strings"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
)

func TestJSONConfigLoader_RejectsUnknownSettings(t *testing.T) {
	cache := make(ConfigCreatorCache)
	if err := cache.RegisterCreator("freedom", func() interface{} {
		return new(FreedomConfig)
	}); err != nil {
		t.Fatal(err)
	}
	loader := NewJSONConfigLoader(cache, "protocol", "settings")

	raw := []byte(`{"protocol": "freedom", "settings": {"unknwn": "value"}}`)
	_, _, err := loader.Load(raw)
	if err == nil {
		t.Fatal("expected error for unknown field in settings, got nil")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected error about unknown field, got: %v", err)
	}
}

func TestJSONConfigLoader_AcceptsValidSettings(t *testing.T) {
	cache := make(ConfigCreatorCache)
	if err := cache.RegisterCreator("freedom", func() interface{} {
		return new(FreedomConfig)
	}); err != nil {
		t.Fatal(err)
	}
	loader := NewJSONConfigLoader(cache, "protocol", "settings")

	raw := []byte(`{"protocol": "freedom", "settings": {"domainStrategy": "AsIs"}}`)
	_, _, err := loader.Load(raw)
	if err != nil {
		t.Fatalf("expected no error for valid settings, got: %v", err)
	}
}

func TestJSONConfigLoader_RejectsUnknownInPlainSettings(t *testing.T) {
	cache := make(ConfigCreatorCache)
	if err := cache.RegisterCreator("freedom", func() interface{} {
		return new(FreedomConfig)
	}); err != nil {
		t.Fatal(err)
	}
	loader := NewJSONConfigLoader(cache, "protocol", "")

	raw := []byte(`{"protocol": "freedom", "unknownKey": "nope"}`)
	_, _, err := loader.Load(raw)
	if err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected error about unknown field, got: %v", err)
	}
}
