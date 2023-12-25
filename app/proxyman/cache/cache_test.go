package cache_test

import (
	"testing"

	. "github.com/xtls/xray-core/app/proxyman/cache"
)

func TestConfigCache(t *testing.T) {
	cache := ConfigCache

	const k = "hello"
	cache.Add(k, "world")
	cache.Add(1, 2)

	exp := "\"world\""
	if c, ok := cache.Get(k); !ok || c != exp {
		t.Logf("<%s> != <%s>", exp, c)
		t.Error("get config error")
	}

	cache.Remove(k)
	if _, ok := cache.Get(k); ok {
		t.Error("delete config error")
	}

	exp = "[2]"
	if c := cache.GetAll(); c != exp {
		t.Logf("<%s> != <%s>", exp, c)
		t.Error("get all config error")
	}

	cache.Refresh()
	if c := cache.GetAll(); c != "[]" {
		t.Error("disable cache error")
	}
	if _, ok := cache.Get(1); ok {
		t.Error("disable cache error")
	}

	cache.Add(k, "world")
	if _, ok := cache.Get(k); ok {
		t.Error("disable cache error")
	}
	if c := cache.GetAll(); c != "[]" {
		t.Error("disable cache error")
	}

	cache.Activate()
	cache.Refresh()
	cache.Add(k, "world")
	if _, ok := cache.Get(k); !ok {
		t.Error("disable cache error")
	}

}
