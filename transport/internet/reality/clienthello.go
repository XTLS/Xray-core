package reality

import (
	"fmt"
	"strings"

	utls "github.com/refraction-networking/utls"
)

const (
	ClientHelloProfileCompactSingleSegment = "compact-single-segment"
	DefaultCompactClientHelloMaxBytes      = uint32(1200)
	maxSingleTLSRecordBytes                = uint32(5 + 16384)
)

// ValidateClientHelloPolicy validates the client-only REALITY ClientHello options.
func ValidateClientHelloPolicy(fingerprint, profile string, maxBytes uint32) error {
	if profile != "" && profile != ClientHelloProfileCompactSingleSegment {
		return fmt.Errorf("REALITY: unknown clientHelloProfile: %s", profile)
	}
	if profile == ClientHelloProfileCompactSingleSegment &&
		fingerprint != "" && fingerprint != "chrome" && !strings.HasPrefix(fingerprint, "hellochrome_") {
		return fmt.Errorf("REALITY: clientHelloProfile %q requires a Chrome fingerprint", profile)
	}
	if maxBytes > maxSingleTLSRecordBytes {
		return fmt.Errorf("REALITY: clientHelloMaxBytes must not exceed %d", maxSingleTLSRecordBytes)
	}
	return nil
}

func applyClientHelloPolicy(uConn *utls.UConn, config *Config) error {
	profile := strings.ToLower(config.ClientHelloProfile)
	maxBytes := config.ClientHelloMaxBytes
	if err := ValidateClientHelloPolicy(strings.ToLower(config.Fingerprint), profile, maxBytes); err != nil {
		return err
	}

	if profile == ClientHelloProfileCompactSingleSegment {
		if maxBytes == 0 {
			maxBytes = DefaultCompactClientHelloMaxBytes
		}
		if err := compactClientHello(uConn); err != nil {
			return err
		}
		if err := uConn.MarshalClientHello(); err != nil {
			return fmt.Errorf("REALITY: failed to marshal compact ClientHello: %w", err)
		}
		if clientHelloRecordSize(uConn) > maxBytes {
			disableClientHelloPadding(uConn)
			if err := uConn.MarshalClientHello(); err != nil {
				return fmt.Errorf("REALITY: failed to marshal unpadded ClientHello: %w", err)
			}
		}
	}

	if maxBytes != 0 {
		size := clientHelloRecordSize(uConn)
		if size > maxBytes {
			return fmt.Errorf("REALITY: ClientHello size %d exceeds configured limit %d", size, maxBytes)
		}
	}
	return nil
}

func compactClientHello(uConn *utls.UConn) error {
	hasX25519KeyShare := false
	for _, extension := range uConn.Extensions {
		switch extension := extension.(type) {
		case *utls.SupportedCurvesExtension:
			extension.Curves = removeHybridCurves(extension.Curves)
			uConn.HandshakeState.Hello.SupportedCurves = extension.Curves
		case *utls.KeyShareExtension:
			extension.KeyShares = removeHybridKeyShares(extension.KeyShares)
			uConn.HandshakeState.Hello.KeyShares = extension.KeyShares
			for _, keyShare := range extension.KeyShares {
				if keyShare.Group == utls.X25519 {
					hasX25519KeyShare = true
				}
			}
		}
	}
	if !hasX25519KeyShare || uConn.HandshakeState.State13.KeyShareKeys.Ecdhe == nil {
		return fmt.Errorf("REALITY: compact ClientHello requires an X25519 key share")
	}
	return nil
}

func removeHybridCurves(curves []utls.CurveID) []utls.CurveID {
	result := curves[:0]
	for _, curve := range curves {
		if curve != utls.X25519MLKEM768 && curve != utls.X25519Kyber768Draft00 {
			result = append(result, curve)
		}
	}
	return result
}

func removeHybridKeyShares(keyShares []utls.KeyShare) []utls.KeyShare {
	result := keyShares[:0]
	for _, keyShare := range keyShares {
		if keyShare.Group != utls.X25519MLKEM768 && keyShare.Group != utls.X25519Kyber768Draft00 {
			result = append(result, keyShare)
		}
	}
	return result
}

func disableClientHelloPadding(uConn *utls.UConn) {
	for _, extension := range uConn.Extensions {
		if padding, ok := extension.(*utls.UtlsPaddingExtension); ok {
			padding.GetPaddingLen = nil
			padding.PaddingLen = 0
			padding.WillPad = false
		}
	}
}

func clientHelloRecordSize(uConn *utls.UConn) uint32 {
	return uint32(5 + len(uConn.HandshakeState.Hello.Raw))
}
