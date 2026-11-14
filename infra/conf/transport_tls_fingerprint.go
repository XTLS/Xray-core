package conf

import (
	"fmt"
	"slices"

	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/transport/internet/browser_dialer"
)

// Match the protocol switches in the dialers before resolving a policy. Paths
// using Go TLS, QUIC, or an external browser cannot apply a uTLS fingerprint.
func (c *TLSConfig) validateFingerprintTransport(network string) error {
	if c.FingerprintWeights == nil {
		return nil
	}
	var alpn []string
	if c.ALPN != nil {
		alpn = []string(*c.ALPN)
	}
	switch network {
	case "tcp", "grpc", "httpupgrade", "websocket":
	case "splithttp", "xdrive", "xdns":
		if slices.Equal(alpn, []string{"h3"}) {
			return fmt.Errorf("TLS: fingerprintWeights is not supported over %s H3/QUIC", network)
		}
	case "masque":
		if !slices.Contains(alpn, "h2") || slices.Contains(alpn, "h3") {
			return fmt.Errorf("TLS: fingerprintWeights requires MASQUE over H2 (alpn must include h2 and exclude h3)")
		}
	default:
		return fmt.Errorf("TLS: fingerprintWeights is not supported by %s", network)
	}
	if network == "websocket" || network == "splithttp" {
		addr := platform.NewEnvFlag(platform.BrowserDialerAddress).GetValue(func() string { return "" })
		if addr != "" || browser_dialer.HasBrowserDialer() {
			return fmt.Errorf("TLS: fingerprintWeights cannot control the browser dialer's TLS handshake")
		}
	}
	return nil
}
