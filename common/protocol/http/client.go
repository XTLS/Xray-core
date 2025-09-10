package http

import (
	"context"
	gohttp "net/http"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// NewClient creates an HTTP client with with internal dialer and using the given sockopt.
// sockopt can only have one or empty.
func NewClient(sockopt ...*internet.SocketConfig) *gohttp.Client {
	var Sockopt *internet.SocketConfig
	switch len(sockopt) {
	case 0:
	case 1:
		Sockopt = sockopt[0]
	default:
		panic("sockopt can only be nil or have one")
	}
	httpClient := &gohttp.Client{
		Transport: &gohttp.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dest, err := net.ParseDestination(network + ":" + addr)
				if err != nil {
					return nil, err
				}
				return internet.DialSystem(ctx, dest, Sockopt)
			},
		},
	}
	return httpClient
}
