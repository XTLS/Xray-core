package tun

// packetRoom is what a tun may need in front of a packet in the buffer that it is read into
const packetRoom = 16

// Tun interface implements tun interface interaction
type Tun interface {
	Start() error
	Close() error
	Name() (string, error)
	Index() (int, error)
	// ReadPacket waits for a packet, reads it into b and returns it
	ReadPacket(b []byte) ([]byte, error)
	// WritePacket writes a packet that is in two parts, the second of which may be empty
	WritePacket(header, payload []byte) error
}
