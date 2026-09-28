package xdns

import (
	"context"
	"time"
)

const (
	resolverTimeout       = 10 * time.Second
	resolverMaxConcurrent = 16
)

type exchangeResolver interface {
	Exchange(context.Context, []byte) ([]byte, error)
	Close() error
}

func hasEncryptedResolver(resolvers []string) bool {
	for _, resolver := range resolvers {
		spec, err := parseResolver(resolver)
		if err == nil && spec.protocol != resolverUDP {
			return true
		}
	}
	return false
}
