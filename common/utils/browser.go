package utils

import (
	"strconv"
	"time"

	"github.com/klauspost/cpuid/v2"
	"github.com/xtls/xray-core/core"
)

func ChromeVersion() int {
	// Chrome 144 released on 2026.1.13, new version every 45 days
	chrome144Release := time.Date(2026, 1, 13, 0, 0, 0, 0, time.UTC)
	// Use CPU features + Xray version as seed for upgrade delay (1-45 days)
	seed := cpuid.CPU.Family + cpuid.CPU.Model + cpuid.CPU.PhysicalCores + cpuid.CPU.LogicalCores + cpuid.CPU.CacheLine + int(core.Version_x) + int(core.Version_y) + int(core.Version_z)
	upgradeDelay := seed%45 + 1
	// First subtract upgrade delay from current date
	userDate := time.Now().AddDate(0, 0, -upgradeDelay)
	// Then calculate Chrome version for that date
	daysSinceRelease := int(userDate.Sub(chrome144Release).Hours() / 24)
	return 144 + daysSinceRelease/45
}

// ChromeUA provides default browser User-Agent. Chrome 144 = Jan 13, 2026, +1 per 45 days.
var ChromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(ChromeVersion()) + ".0.0.0 Safari/537.36"
