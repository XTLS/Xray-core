package utils

import (
	"strconv"
	"time"

	"github.com/klauspost/cpuid/v2"
	"github.com/xtls/xray-core/core"
)

func ChromeVersion() int {
	now := time.Now()
	// Assume Chrome releases on 15th each month, with Jan 2026 being version 144
	// Calculate the latest Chrome version based on current date
	latestVer := 144 + (now.Year()-2026)*12 + int(now.Month()) - 1
	daysSinceRelease := now.Day() - 15
	if daysSinceRelease < 0 {
		latestVer-- // Before 15th, the new version hasn't released yet
		// Days since previous month's release (15th)
		lastDay := time.Date(now.Year(), now.Month(), 0, 0, 0, 0, 0, time.UTC).Day()
		daysSinceRelease = now.Day() + (lastDay - 15)
	}
	if latestVer < 144 {
		latestVer = 144
	}
	// Use CPU features + Xray version as seed
	seed := cpuid.CPU.Family + cpuid.CPU.Model + cpuid.CPU.PhysicalCores + cpuid.CPU.LogicalCores + cpuid.CPU.CacheLine + int(core.Version_x) + int(core.Version_y) + int(core.Version_z)
	// User upgrade delay: 1-30 days uniformly distributed based on seed
	upgradeDelay := seed%30 + 1
	// If user's delay > days since release, they haven't upgraded yet
	if upgradeDelay > daysSinceRelease {
		return latestVer - 1
	}
	return latestVer
}

// ChromeUA provides default browser User-Agent. Chrome 144 = Jan 15, 2026, +1 per month.
var ChromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(ChromeVersion()) + ".0.0.0 Safari/537.36"
