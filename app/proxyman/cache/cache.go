package cache

import (
	"fmt"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common"
	creflect "github.com/xtls/xray-core/common/reflect"
)

var ConfigCache = &configCache{
	m:       new(sync.Mutex),
	ifaces:  make(map[interface{}]interface{}),
	strs:    make(map[interface{}]string),
	stopped: false,
	enable:  false,
}

type configCache struct {
	m       *sync.Mutex
	ifaces  map[interface{}]interface{}
	strs    map[interface{}]string
	stopped bool
	enable  bool
}

func (cc *configCache) Activate() {
	cc.enable = true
	cc.stopped = false
}

func (cc *configCache) Add(key interface{}, config interface{}) {
	if cc.stopped {
		return
	}

	cc.m.Lock()
	defer cc.m.Unlock()
	// double check
	if cc.stopped {
		return
	}
	cc.ifaces[key] = config
}

func (cc *configCache) Get(key interface{}) (string, bool) {
	if cc.stopped {
		return "", false
	}
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
	if cc.stopped {
		return "[]"
	}

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

func (cc *configCache) Refresh() {
	if cc.enable {
		return
	}

	cc.stopped = true
	cc.m.Lock()
	defer cc.m.Unlock()

	cc.ifaces = make(map[interface{}]interface{})
	cc.strs = make(map[interface{}]string)
}

func (cc *configCache) getConfigUnsafe(key interface{}) (string, bool) {
	if s, ok := cc.strs[key]; ok {
		return s, true
	}
	defer delete(cc.ifaces, key)
	if iface, ok := cc.ifaces[key]; ok {
		if s, ok := creflect.MarshalToJson(iface); ok {
			cc.strs[key] = s
			return s, true
		}
	}
	return "", false
}

func init() {
	common.InterceptConfig = ConfigCache.Add
}
