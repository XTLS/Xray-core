package header

import "encoding/binary"

type utp struct {
	header       byte
	extension    byte
	connectionID uint16
}

func (*utp) Size() int {
	return 4
}

func (h *utp) Serialize(b []byte) {
	binary.BigEndian.PutUint16(b, h.connectionID)
	b[2] = h.header
	b[3] = h.extension
}
