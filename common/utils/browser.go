package utils

import (
	"hash/fnv"
	"math"
	"math/rand"
	"strconv"
	"time"
	"net/http"
	"strings"

	"github.com/klauspost/cpuid/v2"
)

func GetRandomizer() *rand.Rand {
	// Seed the PRNG with the hash of CPU info, increasing the overall probable space.
	fnvHash := fnv.New64()
	fnvHash.Write([]byte(strconv.Itoa(cpuid.CPU.Family) + strconv.Itoa(cpuid.CPU.Model) + strconv.Itoa(cpuid.CPU.PhysicalCores) + strconv.Itoa(cpuid.CPU.LogicalCores) + strconv.Itoa(cpuid.CPU.CacheLine) + strconv.Itoa(cpuid.CPU.ThreadsPerCore)))
	return rand.New(rand.NewSource(int64(fnvHash.Sum64())))
}
var globalRng *rand.Rand = GetRandomizer()

// The Chrome version generator will suffer from deviation of a normal distribution.
func ChromeVersion() int {
	// Start from Chrome 144, released on 2026.1.13.
	var startVersion int = 144
	var timeStart int64 = time.Date(2026, 1, 13, 0, 0, 0, 0, time.UTC).Unix() / 86400
	var timeCurrent int64 = time.Now().Unix() / 86400
	var timeDiff int = int((timeCurrent - timeStart - 35)) - int(math.Floor(math.Pow(globalRng.Float64(), 2) * 105))
	return startVersion + (timeDiff / 35) // It's 31.15 currently.
}

var safariMinorMap [25]int = [25]int{0, 0, 0, 1, 1,
	1, 2, 2, 2, 2, 3, 3, 3, 4, 4,
	4, 5, 5, 5, 5, 5, 6, 6, 6, 6}

// The following version generators use deterministic generators, but with the distribution scaled by a curve.
func CurlVersion() string {
	// curl 8.0.0 was released on 20/03/2023.
	var timeCurrent int64 = time.Now().Unix() / 86400
	var timeStart int64 = time.Date(2023, 3, 20, 0, 0, 0, 0, time.UTC).Unix() / 86400
	var timeDiff int = int((timeCurrent - timeStart - 60)) - int(math.Floor(math.Pow(globalRng.Float64(), 2) * 165))
	var minorValue int = int(timeDiff / 57) // The release cadence is actually 56.67 days.
	return "8." + strconv.Itoa(minorValue) + ".0"
}
func FirefoxVersion() int {
	// Firefox 128 ESR was released on 09/07/2023.
	var timeCurrent int64 = time.Now().Unix() / 86400
	var timeStart int64 = time.Date(2024, 7, 29, 0, 0, 0, 0, time.UTC).Unix() / 86400
	var timeDiff = timeCurrent - timeStart - 25 - int64(math.Floor(math.Pow(globalRng.Float64(), 2) * 50))
	return int(timeDiff / 30) + 128
}
func SafariVersion() string {
	var anchoredTime time.Time = time.Now()
	var releaseYear int = anchoredTime.Year()
	var splitPoint time.Time = time.Date(releaseYear, 9, 23, 0, 0, 0, 0, time.UTC)
	var delayedDays = int(math.Floor(math.Pow(globalRng.Float64(), 3) * 75))
	splitPoint = splitPoint.AddDate(0, 0, delayedDays)
	if (anchoredTime.Compare(splitPoint) < 0) {
		releaseYear --
		splitPoint = time.Date(releaseYear, 9, 23, 0, 0, 0, 0, time.UTC)
		splitPoint = splitPoint.AddDate(0, 0, delayedDays)
	}
	var minorVersion = safariMinorMap[(anchoredTime.Unix() - splitPoint.Unix()) / 1296000]
	return strconv.Itoa(releaseYear - 1999) + "." + strconv.Itoa(minorVersion)
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
	//return []int{}
}
func getUngreasedChUa(majorVersion int, forkName string) []string {
	// Set the capacity to 4, the maximum allowed brand size, so Go will never allocate memory twice
	baseChUa := make([]string, 0, 4)
	baseChUa = append(baseChUa, getGreasedChInvalidBrand(majorVersion),
	"\"Chromium\";v=\"" + strconv.Itoa(majorVersion) + "\"")
	switch forkName {
	case "chrome":
		baseChUa = append(baseChUa, "\"Google Chrome\";v=\"" + strconv.Itoa(majorVersion) + "\"")
	case "edge":
		baseChUa = append(baseChUa, "\"Microsoft Edge\";v=\"" + strconv.Itoa(majorVersion) + "\"")
	}
	return baseChUa
}
func getGreasedChUa(majorVersion int, forkName string) string {
	ungreasedCh := getUngreasedChUa(majorVersion, forkName)
	shuffleMap := getGreasedChOrder(len(ungreasedCh), majorVersion)
	shuffledCh := make([]string, len(ungreasedCh))
	for i, e := range shuffleMap {
		shuffledCh[e] = ungreasedCh[i]
	}
	return strings.Join(shuffledCh, ", ")
}

// The code below provides a coherent default browser user agent string based on a CPU-seeded PRNG.
var CurlUA = "curl/" + CurlVersion()
var AnchoredFirefoxVersion = strconv.Itoa(FirefoxVersion())
var FirefoxUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:" + AnchoredFirefoxVersion + ".0) Gecko/20100101 Firefox/" + AnchoredFirefoxVersion + ".0"
var SafariUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/" + SafariVersion() + " Safari/605.1.15"
// Chromium browsers.
var AnchoredChromeVersion = ChromeVersion()
var ChromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(AnchoredChromeVersion) + ".0.0.0 Safari/537.36"
var ChromeUACH = getGreasedChUa(AnchoredChromeVersion, "chrome")
var MSEdgeUA = ChromeUA + "Edg/" + strconv.Itoa(AnchoredChromeVersion) + ".0.0.0"
var MSEdgeUACH = getGreasedChUa(AnchoredChromeVersion, "edge")

func applyMasqueradedHeaders(header http.Header, browser string, variant string) {
	// Browser-specific.
	switch browser {
	case "chrome":
		header["Sec-CH-UA"] = []string{ChromeUACH}
		header["Sec-CH-UA-Mobile"] = []string{"?0"}
		header["Sec-CH-UA-Platform"] = []string{"\"Windows\""}
		header["DNT"] = []string{"1"}
		header.Set("User-Agent", ChromeUA)
		header.Set("Accept-Language", "en-US,en;q=0.9")
	case "edge":
		header["Sec-CH-UA"] = []string{MSEdgeUACH}
		header["Sec-CH-UA-Mobile"] = []string{"?0"}
		header["Sec-CH-UA-Platform"] = []string{"\"Windows\""}
		header["DNT"] = []string{"1"}
		header.Set("User-Agent", MSEdgeUA)
		header.Set("Accept-Language", "en-US,en;q=0.9")
	case "firefox":
		header.Set("User-Agent", FirefoxUA)
		header["DNT"] = []string{"1"}
		header.Set("Accept-Language", "en-US,en;q=0.5")
	case "safari":
		header.Set("User-Agent", SafariUA)
		header.Set("Accept-Language", "en-US,en;q=0.9")
	case "golang":
		// Expose the default net/http header.
		header.Del("User-Agent")
		return
	case "curl":
		header.Set("User-Agent", CurlUA)
		return
	}
	// Context-specific.
	switch variant {
	case "nav":
		if header.Get("Cache-Control") == "" {
			switch browser {
			case "chrome", "edge":
				header.Set("Cache-Control", "max-age=0")
			}
		}
		header.Set("Upgrade-Insecure-Requests", "1")
		if header.Get("Accept") == "" {
			switch browser {
			case "chrome", "edge":
				header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
			case "firefox", "safari":
				header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			}
		}
		header.Set("Sec-Fetch-Site", "none")
		header.Set("Sec-Fetch-Mode", "navigate")
		switch browser {
		case "safari":
		default:
			header.Set("Sec-Fetch-User", "?1")
		}
		header.Set("Sec-Fetch-Dest", "document")
		header.Set("Priority", "u=0, i")
	case "ws":
		header.Set("Sec-Fetch-Mode", "websocket")
		switch browser {
		case "safari":
			// Safari is NOT web-compliant here!
			header.Set("Sec-Fetch-Dest", "websocket")
		default:
			header.Set("Sec-Fetch-Dest", "empty")
		}
		header.Set("Sec-Fetch-Site", "same-origin")
		if header.Get("Cache-Control") == "" {
			header.Set("Cache-Control", "no-cache")
		}
		if header.Get("Pragma") == "" {
			header.Set("Pragma", "no-cache")
		}
		if header.Get("Accept") == "" {
			header.Set("Accept", "*/*")
		}
	case "fetch":
		header.Set("Sec-Fetch-Mode", "cors")
		header.Set("Sec-Fetch-Dest", "empty")
		header.Set("Sec-Fetch-Site", "same-origin")
		if header.Get("Priority") == "" {
			switch browser {
			case "chrome", "edge":
				header.Set("Priority", "u=1, i")
			case "firefox":
				header.Set("Priority", "u=4")
			case "safari":
				header.Set("Priority", "u=3, i")
			}
		}
		if header.Get("Cache-Control") == "" {
			header.Set("Cache-Control", "no-cache")
		}
		if header.Get("Pragma") == "" {
			header.Set("Pragma", "no-cache")
		}
		if header.Get("Accept") == "" {
			header.Set("Accept", "*/*")
		}
	}
}

func TryDefaultHeadersWith(header http.Header, variant string) {
	// The global UA special value handler for transports. Used to be called HandleTransportUASettings.
	// Just a FYI to whoever needing to fix this piece of code after some spontaneous event, I tried to make the two methods separate to let the code be cleaner and more organized.
	if len(header.Values("User-Agent")) < 1 {
		applyMasqueradedHeaders(header, "chrome", variant)
	} else {
		switch header.Get("User-Agent") {
		case "chrome":
			applyMasqueradedHeaders(header, "chrome", variant)
		case "firefox":
			applyMasqueradedHeaders(header, "firefox", variant)
		case "safari":
			applyMasqueradedHeaders(header, "safari", variant)
		case "edge":
			applyMasqueradedHeaders(header, "edge", variant)
		case "curl":
			applyMasqueradedHeaders(header, "curl", variant)
		case "golang":
			applyMasqueradedHeaders(header, "golang", variant)
		}
	}
}
