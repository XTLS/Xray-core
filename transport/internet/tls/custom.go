package tls

import (
	"context"
	"crypto/tls"

	"github.com/xtls/xray-core/common/net"
)

type customClientKey struct{}

type CustomClientFunc func(conn net.Conn, xrayConfig *Config, config *tls.Config) net.Conn

func CustomClientFromContext(ctx context.Context) (CustomClientFunc, bool) {
	client, loaded := ctx.Value(customClientKey{}).(CustomClientFunc)
	return client, loaded
}

func ContextWithCustomClient(ctx context.Context, customClient CustomClientFunc) context.Context {
	return context.WithValue(ctx, customClientKey{}, customClient)
}
