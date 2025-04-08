package tcp

import (
	"context"
	"slices"
	"strings"

	"github.com/hosemorinho412/xray-core/common"
	"github.com/hosemorinho412/xray-core/common/errors"
	"github.com/hosemorinho412/xray-core/common/net"
	"github.com/hosemorinho412/xray-core/common/session"
	"github.com/hosemorinho412/xray-core/transport/internet"
	"github.com/hosemorinho412/xray-core/transport/internet/reality"
	"github.com/hosemorinho412/xray-core/transport/internet/stat"
	"github.com/hosemorinho412/xray-core/transport/internet/tls"
)

func IsFromMitm(str string) bool {
	return strings.ToLower(str) == "frommitm"
}

// Dial dials a new TCP connection to the given destination.
func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	errors.LogInfo(ctx, "dialing TCP to ", dest)
	conn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}

	if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
		mitmServerName := session.MitmServerNameFromContext(ctx)
		mitmAlpn11 := session.MitmAlpn11FromContext(ctx)
		tlsConfig := config.GetTLSConfig(tls.WithDestination(dest))
		if IsFromMitm(tlsConfig.ServerName) {
			tlsConfig.ServerName = mitmServerName
		}
		isFromMitmVerify := false
		if r, ok := tlsConfig.Rand.(*tls.RandCarrier); ok && len(r.VerifyPeerCertInNames) > 0 {
			for i, name := range r.VerifyPeerCertInNames {
				if IsFromMitm(name) {
					isFromMitmVerify = true
					r.VerifyPeerCertInNames[0], r.VerifyPeerCertInNames[i] = r.VerifyPeerCertInNames[i], r.VerifyPeerCertInNames[0]
					r.VerifyPeerCertInNames = r.VerifyPeerCertInNames[1:]
					after := mitmServerName
					for {
						if len(after) > 0 {
							r.VerifyPeerCertInNames = append(r.VerifyPeerCertInNames, after)
						}
						_, after, _ = strings.Cut(after, ".")
						if !strings.Contains(after, ".") {
							break
						}
					}
					slices.Reverse(r.VerifyPeerCertInNames)
					break
				}
			}
		}
		isFromMitmAlpn := len(tlsConfig.NextProtos) == 1 && IsFromMitm(tlsConfig.NextProtos[0])
		if isFromMitmAlpn {
			if mitmAlpn11 {
				tlsConfig.NextProtos[0] = "http/1.1"
			} else {
				tlsConfig.NextProtos = []string{"h2", "http/1.1"}
			}
		}
		if fingerprint := tls.GetFingerprint(config.Fingerprint); fingerprint != nil {
			conn = tls.UClient(conn, tlsConfig, fingerprint)
			if len(tlsConfig.NextProtos) == 1 && tlsConfig.NextProtos[0] == "http/1.1" { // allow manually specify
				err = conn.(*tls.UConn).WebsocketHandshakeContext(ctx)
			} else {
				err = conn.(*tls.UConn).HandshakeContext(ctx)
			}
		} else {
			conn = tls.Client(conn, tlsConfig)
			err = conn.(*tls.Conn).HandshakeContext(ctx)
		}
		if err != nil {
			if isFromMitmVerify {
				return nil, errors.New("MITM freedom RAW TLS: failed to verify Domain Fronting certificate from " + mitmServerName).Base(err).AtWarning()
			}
			return nil, err
		}
		negotiatedProtocol := conn.(tls.Interface).NegotiatedProtocol()
		if isFromMitmAlpn && !mitmAlpn11 && negotiatedProtocol != "h2" {
			conn.Close()
			return nil, errors.New("MITM freedom RAW TLS: unexpected Negotiated Protocol (" + negotiatedProtocol + ") with " + mitmServerName).AtWarning()
		}
	} else if config := reality.ConfigFromStreamSettings(streamSettings); config != nil {
		if conn, err = reality.UClient(conn, config, ctx, dest); err != nil {
			return nil, err
		}
	}

	tcpSettings := streamSettings.ProtocolSettings.(*Config)
	if tcpSettings.HeaderSettings != nil {
		headerConfig, err := tcpSettings.HeaderSettings.GetInstance()
		if err != nil {
			return nil, errors.New("failed to get header settings").Base(err).AtError()
		}
		auth, err := internet.CreateConnectionAuthenticator(headerConfig)
		if err != nil {
			return nil, errors.New("failed to create header authenticator").Base(err).AtError()
		}
		conn = auth.Client(conn)
	}
	return stat.Connection(conn), nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
