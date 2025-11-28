package protocol

import (
	"math/rand"
)

const (
	paddingChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// padding specifies a half-open range [Min, Max).
type padding struct {
	Min int
	Max int
}

func (p padding) String() string {
	n := p.Min + rand.Intn(p.Max-p.Min)
	bs := make([]byte, n)
	for i := range bs {
		bs[i] = paddingChars[rand.Intn(len(paddingChars))]
	}
	return string(bs)
}

var (
	authRequestPadding  = padding{Min: 256, Max: 2048}
	authResponsePadding = padding{Min: 256, Max: 2048}
	tcpRequestPadding   = padding{Min: 64, Max: 512}
	tcpResponsePadding  = padding{Min: 128, Max: 1024}
)
