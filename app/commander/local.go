package commander

import (
	"context"
	"net"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// RequireLocal admits a direct loopback TCP or Unix-socket API connection.
// Routed API links have synthetic addresses and cannot establish local reach.
func RequireLocal(ctx context.Context) error {
	if p, ok := peer.FromContext(ctx); ok {
		// Xray's UnixConnWrapper exposes an unspecified TCP remote address, but
		// retains the actual Unix local address from the accepted socket.
		if _, ok := p.LocalAddr.(*net.UnixAddr); ok {
			return nil
		}
		remote, remoteOK := p.Addr.(*net.TCPAddr)
		local, localOK := p.LocalAddr.(*net.TCPAddr)
		if remoteOK && localOK && remote.IP.IsLoopback() && local.IP.IsLoopback() {
			return nil
		}
	}
	return status.Error(codes.PermissionDenied, "this RPC requires a direct loopback or local Unix-socket API connection")
}
