package header

import "encoding/binary"

type srtp struct {
	header uint16
	number uint16
}

func (*srtp) Size() int {
	return 4
}

func (h *srtp) Serialize(b []byte) {
	h.number++
	binary.BigEndian.PutUint16(b, h.header)
	binary.BigEndian.PutUint16(b[2:], h.number)
}
