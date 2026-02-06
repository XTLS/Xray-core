package utils

import (
	"strconv"
	"time"

	"github.com/klauspost/cpuid/v2"
	"github.com/xtls/xray-core/core"
)

func ChromeVersion() int {
	// Use CPU features + Xray version as seed for upgrade delay (1-30 days)
	seed := cpuid.CPU.Family + cpuid.CPU.Model + cpuid.CPU.PhysicalCores + cpuid.CPU.LogicalCores + cpuid.CPU.CacheLine + int(core.Version_x) + int(core.Version_y) + int(core.Version_z)
	upgradeDelay := seed%30 + 1
	// First subtract upgrade delay from current date
	userDate := time.Now().AddDate(0, 0, -upgradeDelay)
	// Then calculate Chrome version for that date (releases on 15th each month, 2026.1.15 = 144)
	version := 144 + (userDate.Year()-2026)*12 + int(userDate.Month()) - 1
	if userDate.Day() < 15 {
		version--
	}
	return version
}

// ChromeUA provides default browser User-Agent. Chrome 144 = Jan 15, 2026, +1 per month.
var ChromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(ChromeVersion()) + ".0.0.0 Safari/537.36"
