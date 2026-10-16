package internet

func isTCPSocket(network string) bool {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return true
	default:
		return false
	}
}

func isUDPSocket(network string) bool {
	switch network {
	case "udp", "udp4", "udp6":
		return true
	default:
		return false
	}
}

func (v *SocketConfig) ParseTFOValue() int {
	if v.Tfo == 0 {
		return -1
	}
	tfo := int(v.Tfo)
	if tfo < 0 {
		tfo = 0
	}
	return tfo
}

// Dial should fail on bind errors, return this to indicate such errors.
type BindError struct {
	err error
}

func (e *BindError) Unwrap() error {
	return e.err
}

func (e *BindError) Error() string {
	return "failed to bind to interface: " + e.err.Error()
}

func NewBindError(err error) *BindError {
	return &BindError{
		err: err,
	}
}
