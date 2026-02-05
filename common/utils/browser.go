package utils

import (
	"strconv"
	"time"

	"github.com/xtls/xray-core/core"
)

func ChromeVersion() int {
	now := time.Now()
	ver := 143 + (now.Year()-2026)*12 + int(now.Month()) - 1
	if ver < 143 {
		ver = 143
	}
	versionSum := int(core.Version_x + core.Version_y + core.Version_z)
	day := now.Day()
	if day < 15 {
		// Days 1-14: distribute -1 transition uniformly
		transitionDay := 1 + versionSum%14
		if day >= transitionDay {
			ver--
		}
	} else {
		// Days 15 to end of month: distribute +1 transition uniformly
		lastDay := time.Date(now.Year(), now.Month()+1, 0, 0, 0, 0, 0, time.Local).Day()
		daysRange := lastDay - 14
		transitionDay := 15 + versionSum%daysRange
		if day >= transitionDay {
			ver++
		}
	}
	return ver
}

// ChromeUA provides default browser User-Agent. Version 143 = Jan 2026, +1 per month.
var ChromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(ChromeVersion()) + ".0.0.0 Safari/537.36"
