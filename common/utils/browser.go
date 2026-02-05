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
	// Boundary between -1 and +1 zones is distributed between days 15-20
	boundary := 15 + versionSum%6
	if day < boundary {
		// Before boundary: distribute -1 transition uniformly from day 1 to boundary-1
		transitionDay := 1 + versionSum%(boundary-1)
		if day >= transitionDay {
			ver--
		}
	} else {
		// From boundary to end of month: distribute +1 transition uniformly
		lastDay := time.Date(now.Year(), now.Month()+1, 0, 0, 0, 0, 0, time.Local).Day()
		daysRange := lastDay - boundary + 1
		transitionDay := boundary + versionSum%daysRange
		if day >= transitionDay {
			ver++
		}
	}
	return ver
}

// ChromeUA provides default browser User-Agent. Version 143 = Jan 2026, +1 per month.
var ChromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(ChromeVersion()) + ".0.0.0 Safari/537.36"
