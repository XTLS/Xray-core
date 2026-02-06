package utils

import (
	"math/rand"
	"strconv"
	"time"

	"github.com/klauspost/cpuid/v2"
)

func ChromeVersion() int {
	// Use only CPU info as seed for PRNG
	seed := int64(cpuid.CPU.Family + cpuid.CPU.Model + cpuid.CPU.PhysicalCores + cpuid.CPU.LogicalCores + cpuid.CPU.CacheLine)
	rng := rand.New(rand.NewSource(seed))
	// Start from Chrome 144 released on 2026.1.13
	releaseDate := time.Date(2026, 1, 13, 0, 0, 0, 0, time.UTC)
	version := 144
	now := time.Now()
	// Each version has random 25-45 day interval
	for releaseDate.Before(now) {
		releaseDate = releaseDate.AddDate(0, 0, rng.Intn(21)+25)
		version++
	}
	return version - 1
}

// ChromeUA provides default browser User-Agent based on CPU-seeded PRNG.
var ChromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(ChromeVersion()) + ".0.0.0 Safari/537.36"
