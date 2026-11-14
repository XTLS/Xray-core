//go:build amd64 && !purego

package vmess

import (
	"crypto/fips140"

	"golang.org/x/sys/cpu"
)

type schedule [176]byte

//go:noescape
func expand128(key *[16]byte, dec *schedule)

//go:noescape
func decrypt1(rk *schedule, src *[16]byte, dst *[16]byte)

//go:noescape
func decrypt4(rk *schedule, src *[16]byte, dst *[4][16]byte)

type nativeRouteKeys []reducedSchedule

func (k nativeRouteKeys) size() int                         { return len(k) * 68 }
func (k nativeRouteKeys) match(q *[16]byte, now uint64) int { return scanReduced(k, q, now) }
func init() {
	if !cpu.X86.HasAES || !cpu.X86.HasSSE41 || fips140.Enabled() {
		return
	}
	routeKeyBytes = 68
	scanRouteRaw = scanRawStack
	prepareRouteKeys = func(keys [][16]byte) routeKeys {
		result := make(nativeRouteKeys, len(keys))
		for i := range keys {
			var full schedule
			expand128(&keys[i], &full)
			result[i] = reduce(&full)
		}
		return result
	}
}

func scanRawStack(keys [][16]byte, query *[16]byte, now uint64) int {
	var temp [4]schedule
	var out [4][16]byte
	i := 0
	for ; i+4 <= len(keys); i += 4 {
		for lane := range temp {
			expand128(&keys[i+lane], &temp[lane])
		}
		decrypt4(&temp[0], query, &out)
		for lane := range out {
			if valid(&out[lane], now) {
				return i + lane
			}
		}
	}
	for ; i < len(keys); i++ {
		expand128(&keys[i], &temp[0])
		decrypt1(&temp[0], query, &out[0])
		if valid(&out[0], now) {
			return i
		}
	}
	return -1
}
