package noise

// replayWindow is a sliding window tracking previously used nonces.
type replayWindow struct {
	// It is a coincidence that bitmap and highest have the same integer
	// type. highest must be uint64 because that is the type of Noise
	// nonces; but bitmap could conceptually be larger or smaller.
	bitmap  uint64
	highest uint64
}

// CheckAndUpdate checks whether a nonce is acceptable, given the current state
// of the replay window. If acceptable, updates the state to mark the nonce as
// used.
//
// This function must be called only after verifying the integrity of the
// enclosed message.
func (rw *replayWindow) CheckAndUpdate(nonce uint64) bool {
	// The algorithm is adapted from
	// https://datatracker.ietf.org/doc/html/rfc2401#appendix-C.
	// See also the last paragraph of Section 5.4.6 of
	// https://www.wireguard.com/papers/wireguard.pdf.
	if nonce <= rw.highest {
		// nonce is in the past.
		diff := rw.highest - nonce
		if diff >= 64 {
			// nonce is before the window.
			return false
		}
		mask := uint64(1) << diff
		if rw.bitmap&mask != 0 {
			// nonce is within the window, but already used.
			return false
		}
		// nonce is within the window, and not yet used. Mark it used.
		rw.bitmap |= mask
		return true
	} else {
		// nonce is in the future.
		diff := nonce - rw.highest
		// Shift the window.
		rw.bitmap <<= diff // If the shift overflows, bitmap becomes 0.
		rw.highest = nonce
		// Mark this most recent nonce used.
		rw.bitmap |= 1
		return true
	}
}
