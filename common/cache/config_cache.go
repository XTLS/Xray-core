package cache

import (
	"fmt"
	"strings"
	"sync"

	creflect "github.com/xtls/xray-core/common/reflect"
)

type ConfigCache interface {
	Add(key interface{}, config interface{})
	Get(key interface{}) (string, bool)
	Remove(key interface{})
	GetAll() string
}

func NewConfigCache() ConfigCache {
	return &configCache{
		m:      new(sync.Mutex),
		ifaces: make(map[interface{}]interface{}, 0),
		strs:   make(map[interface{}]string),
	}
}

type configCache struct {
	m      *sync.Mutex
	ifaces map[interface{}]interface{}
	strs   map[interface{}]string
}

func (cc *configCache) Add(key interface{}, config interface{}) {
	cc.m.Lock()
	defer cc.m.Unlock()
	cc.ifaces[key] = config
}

func (cc *configCache) Get(key interface{}) (string, bool) {
	cc.m.Lock()
	defer cc.m.Unlock()
	return cc.getConfigUnsafe(key)
}

func (cc *configCache) Remove(key interface{}) {
	cc.m.Lock()
	defer cc.m.Unlock()
	delete(cc.ifaces, key)
	delete(cc.strs, key)
}

func (cc *configCache) GetAll() string {
	cc.m.Lock()
	defer cc.m.Unlock()

	l := len(cc.ifaces)

	// getConfigUnsafe() may delete a key from ifaces
	keys := make([]interface{}, l)
	for key := range cc.ifaces {
		keys = append(keys, key)
	}

	arr := make([]string, 0)
	for key := range keys {
		if c, ok := cc.getConfigUnsafe(key); ok {
			arr = append(arr, c)
		}
	}

	return fmt.Sprintf("[%s]", strings.Join(arr, ",\n"))
}

func (cc *configCache) getConfigUnsafe(key interface{}) (string, bool) {
	if s, ok := cc.strs[key]; ok {
		return s, true
	}
	if iface, ok := cc.ifaces[key]; ok {
		if s, ok := creflect.MarshalToJson(iface); ok {
			cc.strs[key] = s
			return s, true
		} else {
			delete(cc.ifaces, key)
		}
	}
	return "", false
}
