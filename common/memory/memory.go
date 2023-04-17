package memory

import (
	"runtime"
	"runtime/debug"
	"time"

	"github.com/xtls/xray-core/common/platform"
)

var (
	gcInterval time.Duration
	preGCTime  time.Time
)

func GCCheck() {
	now := time.Now()
	if now.Sub(preGCTime) < gcInterval {
		return
	}
	preGCTime = now
	go func() {
		runtime.GC()
		debug.FreeOSMemory()
		newError("forceGC").AtInfo().WriteToLog()
	}()
}

func ForceGCEnabled() bool {
	const key = "xray.inbound.memory.forceGC"
	const defaultValue = 0
	forceGC := platform.EnvFlag{
		Name:    key,
		AltName: platform.NormalizeEnvName(key),
	}.GetValueAsInt(defaultValue)
	return forceGC != 0
}

func InitGCCheck(maxMemory int64, checkInterval time.Duration) {
	debug.SetGCPercent(10)
	debug.SetMemoryLimit(maxMemory)
	gcInterval = checkInterval
	preGCTime = time.Now()
}
