package lasthandshake

import (
	context "context"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
)

type LastHandshake struct {
	mu       sync.RWMutex
	lastTime time.Time
}

var Global = &LastHandshake{
	lastTime: time.Unix(0, 0),
}

func NewManager(ctx context.Context, config *Config) *LastHandshake {
	Global.lastTime = time.Unix(0, 0)
	return Global
}

func (lh *LastHandshake) Record() {
	lh.mu.Lock()
	defer lh.mu.Unlock()
	lh.lastTime = time.Now()
}

func (lh *LastHandshake) Get() time.Time {
	lh.mu.RLock()
	defer lh.mu.RUnlock()
	return lh.lastTime
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewManager(ctx, config.(*Config)), nil
	}))
}
