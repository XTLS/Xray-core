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
	// Distribute version transition across days 15 to end of month based on core version
	lastDay := time.Date(now.Year(), now.Month()+1, 0, 0, 0, 0, 0, time.Local).Day()
	daysRange := lastDay - 14 // days from 15 to lastDay
	transitionDay := 15 + int(core.Version_x+core.Version_y+core.Version_z)%daysRange
	if now.Day() >= transitionDay {
		ver++
	}
	return ver
}

// ChromeUA provides default browser User-Agent. Version 143 = Jan 2026, +1 per month.
var ChromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(ChromeVersion()) + ".0.0.0 Safari/537.36"
