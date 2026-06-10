package encoding

import (
	"context"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

func remoteAddrFromContext(ctx context.Context, trusted []string) net.Addr {
	var remoteAddr net.Addr
	if pr, ok := peer.FromContext(ctx); ok {
		remoteAddr = pr.Addr
	} else {
		remoteAddr = &net.TCPAddr{
			IP:   []byte{0, 0, 0, 0},
			Port: 0,
		}
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return remoteAddr
	}

	key := "X-Real-IP"
	values := md.Get(key)
	if len(values) == 0 || values[0] == "" {
		key = "X-Forwarded-For"
		values = md.Get(key)
	}
	if len(values) == 0 || values[0] == "" {
		return remoteAddr
	}

	isTrusted := false
	for _, t := range trusted {
		if len(md.Get(t)) > 0 {
			isTrusted = true
			break
		}
	}
	if !isTrusted {
		if len(trusted) == 0 {
			errors.LogWarning(context.Background(), `received "`, key, `" from `, remoteAddr, ` but "sockopt.trustedXForwardedFor" is not configured; ignoring it and using the real remote address`)
		} else {
			errors.LogError(context.Background(), `ignored potentially forged "`, key, `" from `, remoteAddr, `: `, values[0])
		}
		return remoteAddr
	}

	forwardedIP := values[0]
	if key == "X-Forwarded-For" {
		if idx := strings.IndexByte(forwardedIP, ','); idx >= 0 {
			forwardedIP = forwardedIP[:idx]
		}
	}

	forwardedAddr := net.ParseAddress(forwardedIP)
	if forwardedAddr.Family().IsIP() {
		remoteAddr = &net.TCPAddr{
			IP:   forwardedAddr.IP(),
			Port: 0,
		}
	}
	return remoteAddr
}
