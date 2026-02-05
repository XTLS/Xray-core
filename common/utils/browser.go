package utils

import (
	"strconv"
	"time"

	"github.com/klauspost/cpuid/v2"
)

func ChromeVersion() int {
	now := time.Now()
	ver := 143 + (now.Year()-2026)*12 + int(now.Month()) - 1
	if ver < 143 {
		ver = 143
	}
	// Use CPU features as machine-specific seed
	seed := cpuid.CPU.Family + cpuid.CPU.Model + cpuid.CPU.PhysicalCores + cpuid.CPU.LogicalCores + cpuid.CPU.CacheLine
	// Boundary day uniformly distributed between 15-20 based on seed
	boundary := 15 + seed%6
	day := now.Day()
	if day < boundary {
		// Before boundary: uniformly distributed -1 within days 1 to boundary-1
		if seed%(boundary-1) < day {
			ver--
		}
	} else {
		// After boundary: avoid downgrade
		// If seed % 3 == 0, it would have gotten -1 before boundary, so allow -1/0/+1
		// Otherwise, it didn't get -1 before, so only allow 0/+1
		if seed%3 == 0 {
			// Was -1 before boundary, can be -1/0/+1 after
			switch seed % 3 {
			case 0:
				ver--
			case 2:
				ver++
			}
		} else {
			// Was not -1 before boundary, can only be 0/+1 after
			if seed%2 == 1 {
				ver++
			}
		}
	}
	return ver
}

// ChromeUA provides default browser User-Agent. Version 143 = Jan 2026, +1 per month.
var ChromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(ChromeVersion()) + ".0.0.0 Safari/537.36"
