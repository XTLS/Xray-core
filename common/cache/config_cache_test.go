package cache_test

import (
	"testing"

	. "github.com/xtls/xray-core/common/cache"
)

func TestConfigCache(t *testing.T) {
	cache := NewConfigCache()

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
}
