package transport

import "github.com/xmplusdev/xray-core/common/buf"

// Link is a utility for connecting between an inbound and an outbound proxy handler.
type Link struct {
	Reader buf.Reader
	Writer buf.Writer
}
