package memory

import (
	"runtime"
	"runtime/debug"
	"time"

	"github.com/xtls/xray-core/common/platform"
)

var (
	memoryMaxValue      int64
	memoryCheckInterval time.Duration
	memoryLastCheck     time.Time
)

func MemoryCheck() error {
	if memoryMaxValue <= 0 {
		return nil
	}
	now := time.Now()
	if now.Sub(memoryLastCheck) < memoryCheckInterval {
		return nil
	}
	memoryLastCheck = now
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	usedMemory := int64(memStats.StackInuse + memStats.HeapInuse + memStats.HeapIdle - memStats.HeapReleased)
	if usedMemory > memoryMaxValue {
		go func() {
			debug.FreeOSMemory()
		}()
		return newError("out of memory")
	}
	return nil
}

func MemoryCheckEnabled() bool {
	const key = "xray.inbound.memory.check"
	const defaultValue = 0
	checkValue := platform.EnvFlag{
		Name:    key,
		AltName: platform.NormalizeEnvName(key),
	}.GetValueAsInt(defaultValue)
	return checkValue != 0
}

func InitMemoryCheck(maxMemory int64, checkInterval time.Duration) {
	if maxMemory > 0 {
		debug.SetGCPercent(10)
		debug.SetMemoryLimit(maxMemory)
		memoryMaxValue = maxMemory
		memoryCheckInterval = checkInterval
		memoryLastCheck = time.Now()
	}
}
