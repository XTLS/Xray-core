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

// segmenter is a tun whose other side takes TCP segments that are larger than the MTU,
// splits them only if it has to send them on, and completes their checksum then
type segmenter interface {
	// Segments reports whether WriteSegment can be used
	Segments() bool
	// WriteSegment writes a packet with a TCP segment whose payload is in parts, to be sent on with mss bytes
	// of it at most in one. Its checksum is that of the pseudo-header only, not inverted
	WriteSegment(header []byte, payload [][]byte, mss int) error
}
