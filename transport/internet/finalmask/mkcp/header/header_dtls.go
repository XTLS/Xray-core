package header

type dtls struct {
	epoch    uint16
	length   uint16
	sequence uint32
}

func (*dtls) Size() int {
	return 1 + 2 + 2 + 6 + 2
}

func (h *dtls) Serialize(b []byte) {
	b[0] = 23
	b[1] = 254
	b[2] = 253
	b[3] = byte(h.epoch >> 8)
	b[4] = byte(h.epoch)
	b[5] = 0
	b[6] = 0
	b[7] = byte(h.sequence >> 24)
	b[8] = byte(h.sequence >> 16)
	b[9] = byte(h.sequence >> 8)
	b[10] = byte(h.sequence)
	h.sequence++
	b[11] = byte(h.length >> 8)
	b[12] = byte(h.length)
	h.length += 17
	if h.length > 100 {
		h.length -= 50
	}
}
