package utils

import (
	"math/rand"
	"strconv"
	"time"
	"net/http"

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
var AnchoredChromeVersion = ChromeVersion()
var ChromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(AnchoredChromeVersion) + ".0.0.0 Safari/537.36"

func getValidManglingChar() string {
	// Valid characters for the mangled Sec-CH-UA header
	return string(" ,-_:;()"[rand.Int() & 7]);
}

// It would be better to have the three parts ordered randomly upon generation
var ChromeUACH = "\"Google Chrome\";v=\"" + strconv.Itoa(AnchoredChromeVersion) + "\", \"Chromium\";v=\"" + strconv.Itoa(AnchoredChromeVersion) + "\", \"Not" + getValidManglingChar() + "A" + getValidManglingChar() + "Brand\";v=\"9" + string("6789"[rand.Int() & 3]) + "\""

func ApplyDefaultHeaders(header http.Header, browser string, variant string) {
	// Browser-specific
	switch browser {
	case "chrome":
		header.Set("User-Agent", ChromeUA)
		header.Set("Sec-CH-UA", ChromeUACH)
		header.Set("Sec-CH-UA-Mobile", "?0")
		header.Set("Sec-CH-UA-Platform", "Windows")
		header.Set("Accept-Language", "en-US,en;q=0.9")
	case "firefox":
		header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0") // Can have a Firefox ESR version generator later
		header.Set("Accept-Language", "en-US,en;q=0.5")
	}
	// variant-specific
	switch variant {
	case "nav":
		header.Set("Sec-Fetch-Mode", "navigate")
		header.Set("Sec-Fetch-Dest", "document")
		header.Set("Sec-Fetch-Site", "none")
		header.Set("Upgrade-Insecure-Requests", "1")
		header.Set("Priority", "u=0, i")
		if header.Get("Cache-Control") == "" {
			switch browser {
			case "chrome":
				header.Set("Cache-Control", "max-age=0")
			}
		}
		if header.Get("Accept") == "" {
			switch browser {
			case "chrome":
				header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
			case "firefox":
				header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			}
		}
	case "ws":
		header.Set("Sec-Fetch-Mode", "websocket")
		header.Set("Sec-Fetch-Dest", "empty")
		header.Set("Sec-Fetch-Site", "cross-site")
		if header.Get("Cache-Control") == "" {
			header.Set("Cache-Control", "no-cache")
		}
		if header.Get("Accept") == "" {
			header.Set("Accept", "*/*")
		}
	case "fetch":
		header.Set("Sec-Fetch-Mode", "cors")
		header.Set("Sec-Fetch-Dest", "empty")
		header.Set("Sec-Fetch-Site", "cross-site")
		if header.Get("Priority") == "" {
			switch browser {
			case "chrome":
				header.Set("Priority", "u=1, i")
			case "firefox":
				header.Set("Priority", "u=4")
			}
		}
		if header.Get("Cache-Control") == "" {
			header.Set("Cache-Control", "no-cache")
		}
		if header.Get("Accept") == "" {
			header.Set("Accept", "*/*")
		}
	}
	header.Set("Sec-Fetch-User", "?1")
}
