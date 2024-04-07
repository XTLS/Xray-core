package drain

import "io"

//go:generate go run github.com/GFW-knocker/Xray-core/common/errors/errorgen

type Drainer interface {
	AcknowledgeReceive(size int)
	Drain(reader io.Reader) error
}
