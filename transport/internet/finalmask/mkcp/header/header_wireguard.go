package header

type wireguard struct{}

func (*wireguard) Size() int {
	return 4
}

func (h *wireguard) Serialize(b []byte) {
	b[0] = 0x04
	b[1] = 0x00
	b[2] = 0x00
	b[3] = 0x00
}
