package bytes

import (
	"strconv"
	"strings"
	"unicode"
)

// Simple size conversion
const (
	BYTE = 1 << (10 * iota)
	KIBIBYTE
	MEBIBYTE
	GIBIBYTE

	KILOBYTE = BYTE * 1000
	MEGABYTE = KILOBYTE * 1000
	GIGABYTE = MEGABYTE * 1000
)

var invalidByteQuantityError = newError("only accept byte like G/GB/GiB/Gbps M/MB/MiB/Mpbs, K/KB/KiB/Kbps, B/Bits").AtError()

// String to byte
func ToBytes(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)

	i := strings.IndexFunc(s, unicode.IsLetter)

	if i == -1 {
		return 0, invalidByteQuantityError
	}

	bytesString, multiple := s[:i], s[i:]
	bytes, err := strconv.ParseFloat(bytesString, 64)
	if err != nil || bytes < 0 {
		return 0, invalidByteQuantityError
	}

	switch multiple {
	case "g", "gbps", "gbits":
		return uint64(bytes * GIGABYTE / 8), nil
	case "gb", "gigabytes":
		return uint64(bytes * GIGABYTE), nil
	case "gib", "gibibytes":
		return uint64(bytes * GIBIBYTE), nil

	case "m", "mbps", "mbits":
		return uint64(bytes * MEGABYTE / 8), nil
	case "mb", "megabytes":
		return uint64(bytes * MEGABYTE), nil
	case "mib", "mebibytes":
		return uint64(bytes * MEBIBYTE), nil

	case "k", "kbps", "kbits":
		return uint64(bytes * KILOBYTE / 8), nil
	case "kb", "kilobytes":
		return uint64(bytes * KILOBYTE), nil
	case "kib", "kibibytes":
		return uint64(bytes * KIBIBYTE), nil

	case "bps", "bits":
		return uint64(bytes / 8), nil
	case "b", "bytes":
		return uint64(bytes), nil

	default:
		return 0, invalidByteQuantityError
	}
}
