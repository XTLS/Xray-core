package bbr

import "github.com/apernet/quic-go/congestion"

// A Clock returns the current time
type Clock interface {
	Now() congestion.Time
}

// DefaultClock implements the Clock interface using the Go stdlib clock.
type DefaultClock struct{}

var _ Clock = DefaultClock{}

// Now gets the current time
func (DefaultClock) Now() congestion.Time {
	return congestion.Now()
}
