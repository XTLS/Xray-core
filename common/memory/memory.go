package memory

import (
	"runtime/debug"
	"time"

	"github.com/xtls/xray-core/common/platform"
)

func forceFree(interval time.Duration) {
	go func() {
		for {
			time.Sleep(interval)
			debug.FreeOSMemory()
			newError("forceFree").AtDebug().WriteToLog()
		}
	}()
}

func readForceFreeInterval() int {
	const key = "XRAY_MEMORY_FORCEFREE"
	const defaultValue = 0
	interval := platform.EnvFlag{
		Name:    key,
		AltName: platform.NormalizeEnvName(key),
	}.GetValueAsInt(defaultValue)
	return interval
}

func InitForceFree(maxMemory int64) {
	debug.SetGCPercent(10)
	debug.SetMemoryLimit(maxMemory)
	interval := readForceFreeInterval()
	if interval > 0 {
		duration := time.Duration(interval) * time.Second
		forceFree(duration)
	}
}
