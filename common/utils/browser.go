package utils

import (
	"math/rand"
	"strconv"
	"time"
	"net/http"
	"strings"
	"fmt"

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

// The full Chromium brand GREASE implementation
var clientHintGreaseNA = []string{" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"}
var clientHintVersionNA = []string{"8", "99", "24"}
var clientHintShuffle3 = [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
var clientHintShuffle4 = [][4]int{
	{0, 1, 2, 3}, {0, 1, 3, 2}, {0, 2, 1, 3}, {0, 2, 3, 1}, {0, 3, 1, 2}, {0, 3, 2, 1},
	{1, 0, 2, 3}, {1, 0, 3, 2}, {1, 2, 0, 3}, {1, 2, 3, 0}, {1, 3, 0, 2}, {1, 3, 2, 0},
	{2, 0, 1, 3}, {2, 0, 3, 1}, {2, 1, 0, 3}, {2, 1, 3, 0}, {2, 3, 0, 1}, {2, 3, 1, 0},
	{3, 0, 1, 2}, {3, 0, 2, 1}, {3, 1, 0, 2}, {3, 1, 2, 0}, {3, 2, 0, 1}, {3, 2, 1, 0}}
func getGreasedChInvalidBrand(seed int) string {
	return "\"Not" + clientHintGreaseNA[seed % len(clientHintGreaseNA)] + "A" + clientHintGreaseNA[(seed + 1) % len(clientHintGreaseNA)] + "Brand\";v=\"" + clientHintVersionNA[seed % len(clientHintVersionNA)] + "\"";
}
func getGreasedChOrder(brandLength int, seed int) []int {
	switch brandLength {
		case 1:
			return []int{0}
		case 2:
			return []int{seed % brandLength, (seed + 1) % brandLength}
		case 3:
			return clientHintShuffle3[seed % len(clientHintShuffle3)][:]
		default:
			return clientHintShuffle4[seed % len(clientHintShuffle4)][:]
	}
	return []int{}
}
func getUngreasedChUa(majorVersion int) []string {
	return []string {getGreasedChInvalidBrand(majorVersion),
	"\"Chromium\";v=\"" + strconv.Itoa(majorVersion) + "\"",
	"\"Google Chrome\";v=\"" + strconv.Itoa(majorVersion) + "\""}
}
func getGreasedChUa(majorVersion int) string {
	rawCh := getUngreasedChUa(majorVersion)
	shuffleMap := getGreasedChOrder(len(rawCh), majorVersion)
	shuffledCh := make([]string, len(rawCh))
	for i, e := range shuffleMap {
		shuffledCh[e] = rawCh[i]
	}
	return strings.Join(shuffledCh, ", ")
}

// ChromeUA provides default browser User-Agent based on CPU-seeded PRNG.
var AnchoredChromeVersion = ChromeVersion()
var ChromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(AnchoredChromeVersion) + ".0.0.0 Safari/537.36"
// It would be better to have the three parts ordered randomly upon generation
var ChromeUACH = getGreasedChUa(AnchoredChromeVersion)

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
	for key, value := range header {
		fmt.Println("Added header - " + key + ": " + value)
	}
}
