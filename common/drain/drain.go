package drain

import "io"

//go:generate go run github.com/4nd3r5on/Xray-core/common/errors/errorgen

type Drainer interface {
	AcknowledgeReceive(size int)
	Drain(reader io.Reader) error
}
