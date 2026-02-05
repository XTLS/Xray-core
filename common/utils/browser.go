package utils

import (
	"strconv"
	"time"

	"github.com/klauspost/cpuid/v2"
	"github.com/xtls/xray-core/core"
)

func ChromeVersion() int {
	now := time.Now()
	baseVer := 143 + (now.Year()-2026)*12 + int(now.Month()) - 1
	if baseVer < 143 {
		baseVer = 143
	}
	ver := baseVer
	// Use CPU features + Xray version as seed (version changes ensure occasional different "upgrade strategies")
	seed := cpuid.CPU.Family + cpuid.CPU.Model + cpuid.CPU.PhysicalCores + cpuid.CPU.LogicalCores + cpuid.CPU.CacheLine + int(core.Version_x) + int(core.Version_y) + int(core.Version_z)
	// Boundary day uniformly distributed between 15-20 based on seed
	boundary := 15 + seed%6
	day := now.Day()
	if day < boundary {
		// Before boundary: uniformly distributed -1 within days 1 to boundary-1
		if seed%(boundary-1) < day {
			ver--
		}
	} else {
		// After boundary: uniformly distributed +1 within days boundary to lastDay
		lastDay := time.Date(now.Year(), now.Month()+1, 0, 0, 0, 0, 0, time.UTC).Day()
		daysInRange := lastDay - boundary + 1
		if seed%daysInRange < day-boundary+1 {
			ver++
		}
	}
	// Subtract base version mod 2 to avoid month-end upgrade followed by month-start downgrade
	return ver - baseVer%2
}

// ChromeUA provides default browser User-Agent. Version 143 = Jan 2026, +1 per month.
var ChromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(ChromeVersion()) + ".0.0.0 Safari/537.36"
