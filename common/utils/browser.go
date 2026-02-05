package utils

import (
	"strconv"
	"time"

	"github.com/klauspost/cpuid/v2"
	"github.com/xtls/xray-core/core"
)

func ChromeVersion() int {
	now := time.Now()
	ver := 143 + (now.Year()-2026)*12 + int(now.Month()) - 1
	if ver < 143 {
		ver = 143
	}
	// Combine core version with CPU ID for machine-specific seed
	seed := int(core.Version_x+core.Version_y+core.Version_z) + cpuid.CPU.Family + cpuid.CPU.Model
	// 1/3 probability each for -1, 0, +1 based on seed % 3
	switch seed % 3 {
	case 0:
		ver--
	case 2:
		ver++
	}
	return ver
}

// ChromeUA provides default browser User-Agent. Version 143 = Jan 2026, +1 per month.
var ChromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(ChromeVersion()) + ".0.0.0 Safari/537.36"
