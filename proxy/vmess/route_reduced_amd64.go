//go:build amd64 && !purego

package vmess

// Compact AES-128 schedule retaining all ten rounds.
type reducedSchedule [68]byte

//go:noescape
func decryptReduced4(rk *reducedSchedule, src *[16]byte, dst *[4][16]byte)

func reduce(full *schedule) reducedSchedule {
	var r reducedSchedule
	copy(r[:16], full[:16])
	for round := 1; round <= 9; round++ {
		copy(r[16+(round-1)*4:], full[round*16:round*16+4])
	}
	copy(r[52:], full[160:])
	return r
}

func scanReduced(keys []reducedSchedule, query *[16]byte, now uint64) int {
	var out [4][16]byte
	i := 0
	for ; i+4 <= len(keys); i += 4 {
		decryptReduced4(&keys[i], query, &out)
		for lane := range out {
			if valid(&out[lane], now) {
				return i + lane
			}
		}
	}
	if i < len(keys) {
		var tail [4]reducedSchedule
		copy(tail[:], keys[i:])
		decryptReduced4(&tail[0], query, &out)
		for lane := 0; i+lane < len(keys); lane++ {
			if valid(&out[lane], now) {
				return i + lane
			}
		}
	}
	return -1
}
