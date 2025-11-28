package hyutils

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	Byte     = 1
	Kilobyte = Byte * 1000
	Megabyte = Kilobyte * 1000
	Gigabyte = Megabyte * 1000
	Terabyte = Gigabyte * 1000
)

// StringToBps converts a string to a bandwidth value in bytes per second.
// E.g. "100 Mbps", "512 kbps", "1g" are all valid.
func StringToBps(s string) (uint64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	spl := 0
	for i, c := range s {
		if c < '0' || c > '9' {
			spl = i
			break
		}
	}
	if spl == 0 {
		// No unit or no value
		return 0, errors.New("invalid format")
	}
	v, err := strconv.ParseUint(s[:spl], 10, 64)
	if err != nil {
		return 0, err
	}
	unit := strings.TrimSpace(s[spl:])

	switch strings.ToLower(unit) {
	case "b", "bps":
		return v * Byte / 8, nil
	case "k", "kb", "kbps":
		return v * Kilobyte / 8, nil
	case "m", "mb", "mbps":
		return v * Megabyte / 8, nil
	case "g", "gb", "gbps":
		return v * Gigabyte / 8, nil
	case "t", "tb", "tbps":
		return v * Terabyte / 8, nil
	default:
		return 0, errors.New("unsupported unit")
	}
}

// ConvBandwidth handles both string and int types for bandwidth.
// When using string, it will be parsed as a bandwidth string with units.
// When using int, it will be parsed as a raw bandwidth in bytes per second.
// It does NOT support float types.
func ConvBandwidth(bw interface{}) (uint64, error) {
	switch bwT := bw.(type) {
	case string:
		return StringToBps(bwT)
	case int:
		return uint64(bwT), nil
	default:
		return 0, fmt.Errorf("invalid type %T for bandwidth", bwT)
	}
}
