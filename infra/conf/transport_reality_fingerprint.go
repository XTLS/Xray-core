package conf

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"fmt"
	"slices"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// Validate every candidate before consulting the process-wide selection cache.
// Building a ClientHello is local: no connection is opened and no handshake is
// sent. Match the session ID and key-share requirements of reality.UClient.
func validateREALITYFingerprintWeights(weights FingerprintWeights) error {
	policy, err := weights.policy()
	if err != nil {
		return fmt.Errorf("REALITY: %w", err)
	}
	for _, entry := range policy.entries {
		fingerprint := tls.GetFingerprint(entry.name)
		conn := utls.UClient(nil, &utls.Config{
			ServerName:             "example.com",
			SessionTicketsDisabled: true,
		}, *fingerprint)
		if err := conn.BuildHandshakeState(); err != nil {
			return fmt.Errorf("REALITY: fingerprintWeights candidate %q: build ClientHello: %w", entry.name, err)
		}
		hello := conn.HandshakeState.Hello
		if hello == nil || !slices.Contains(hello.SupportedVersions, uint16(utls.VersionTLS13)) ||
			len(hello.SessionId) != 32 || len(hello.Raw) < 71 {
			return fmt.Errorf("REALITY: fingerprintWeights candidate %q requires a TLS 1.3 ClientHello with a 32-byte session ID", entry.name)
		}
		keys := conn.HandshakeState.State13.KeyShareKeys
		if keys == nil {
			return fmt.Errorf("REALITY: fingerprintWeights candidate %q has no TLS 1.3 key share", entry.name)
		}
		key := keys.Ecdhe
		if key == nil {
			key = keys.MlkemEcdhe
		}
		if key == nil || key.Curve() != ecdh.X25519() {
			return fmt.Errorf("REALITY: fingerprintWeights candidate %q requires an X25519-compatible key share", entry.name)
		}
		// The current REALITY server requires this hybrid share before any
		// standalone X25519 share. An older browser profile can satisfy the
		// client's key derivation requirements yet be rejected by the server.
		hybrid := false
		for _, share := range hello.KeyShares {
			if share.Group == utls.X25519 {
				break
			}
			if share.Group == utls.X25519MLKEM768 && len(share.Data) == mlkem.EncapsulationKeySize768+32 {
				hybrid = true
				break
			}
		}
		if !hybrid {
			return fmt.Errorf("REALITY: fingerprintWeights candidate %q requires X25519MLKEM768 before X25519 for current REALITY servers", entry.name)
		}
	}
	return nil
}
