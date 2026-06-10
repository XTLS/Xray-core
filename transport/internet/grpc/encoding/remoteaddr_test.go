package encoding

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

func TestRemoteAddrFromContext(t *testing.T) {
	tests := []struct {
		name                  string
		metadata              metadata.MD
		trustedXForwardedFor  []string
		expectedRemoteAddress string
	}{
		{
			name:                  "ignore X-Real-IP without trusted header",
			metadata:              metadata.Pairs("X-Real-IP", "1.1.1.1"),
			expectedRemoteAddress: "127.0.0.1:12345",
		},
		{
			name:                  "trust X-Real-IP when configured",
			metadata:              metadata.Pairs("X-Real-IP", "1.1.1.1"),
			trustedXForwardedFor:  []string{"X-Real-IP"},
			expectedRemoteAddress: "1.1.1.1:0",
		},
		{
			name:                  "trust X-Forwarded-For when configured",
			metadata:              metadata.Pairs("X-Forwarded-For", "2.2.2.2, 3.3.3.3"),
			trustedXForwardedFor:  []string{"X-Forwarded-For"},
			expectedRemoteAddress: "2.2.2.2:0",
		},
		{
			name:                  "trust X-Forwarded-For with trusted marker",
			metadata:              metadata.Pairs("X-Forwarded-For", "4.4.4.4", "X-Trusted-CDN", "1"),
			trustedXForwardedFor:  []string{"X-Trusted-CDN"},
			expectedRemoteAddress: "4.4.4.4:0",
		},
		{
			name:                  "ignore X-Forwarded-For without trusted marker",
			metadata:              metadata.Pairs("X-Forwarded-For", "5.5.5.5"),
			trustedXForwardedFor:  []string{"X-Trusted-CDN"},
			expectedRemoteAddress: "127.0.0.1:12345",
		},
		{
			name:                  "prefer X-Real-IP over X-Forwarded-For",
			metadata:              metadata.Pairs("X-Real-IP", "6.6.6.6", "X-Forwarded-For", "7.7.7.7", "X-Trusted-CDN", "1"),
			trustedXForwardedFor:  []string{"X-Trusted-CDN"},
			expectedRemoteAddress: "6.6.6.6:0",
		},
		{
			name:                  "do not parse X-Real-IP as a list",
			metadata:              metadata.Pairs("X-Real-IP", "8.8.8.8, 9.9.9.9", "X-Trusted-CDN", "1"),
			trustedXForwardedFor:  []string{"X-Trusted-CDN"},
			expectedRemoteAddress: "127.0.0.1:12345",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := peer.NewContext(metadata.NewIncomingContext(context.Background(), test.metadata), &peer.Peer{
				Addr: &net.TCPAddr{
					IP:   net.ParseIP("127.0.0.1"),
					Port: 12345,
				},
			})
			remoteAddr := remoteAddrFromContext(ctx, test.trustedXForwardedFor)
			if remoteAddr.String() != test.expectedRemoteAddress {
				t.Fatalf("unexpected remote address: %s", remoteAddr.String())
			}
		})
	}
}
