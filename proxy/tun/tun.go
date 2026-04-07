package tun

// Tun interface implements tun interface interaction
type Tun interface {
	Start() error
	Close() error
}
