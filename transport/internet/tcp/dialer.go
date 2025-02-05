package tcp

import (
	"context"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
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
		tlsConfig := config.GetTLSConfig(tls.WithDestination(dest))
		if IsFromMitm(tlsConfig.ServerName) {
			tlsConfig.ServerName = session.MitmServerNameFromContext(ctx)
		}
		if r, ok := tlsConfig.Rand.(*tls.RandCarrier); ok && len(r.VerifyPeerCertInNames) > 0 && IsFromMitm(r.VerifyPeerCertInNames[0]) {
			r.VerifyPeerCertInNames = r.VerifyPeerCertInNames[1:]
			after := session.MitmServerNameFromContext(ctx)
			for {
				if !strings.Contains(after, ".") {
					break
				}
				r.VerifyPeerCertInNames = append(r.VerifyPeerCertInNames, after)
				_, after, _ = strings.Cut(after, ".")
			}
		}
		if fingerprint := tls.GetFingerprint(config.Fingerprint); fingerprint != nil {
			conn = tls.UClient(conn, tlsConfig, fingerprint)
			if len(tlsConfig.NextProtos) == 1 && (tlsConfig.NextProtos[0] == "http/1.1" || (IsFromMitm(tlsConfig.NextProtos[0]) && session.MitmAlpn11FromContext(ctx))) {
				if err := conn.(*tls.UConn).WebsocketHandshakeContext(ctx); err != nil {
					return nil, err
				}
			} else {
				if err := conn.(*tls.UConn).HandshakeContext(ctx); err != nil {
					return nil, err
				}
			}
		} else {
			if len(tlsConfig.NextProtos) == 1 && IsFromMitm(tlsConfig.NextProtos[0]) {
				if session.MitmAlpn11FromContext(ctx) {
					tlsConfig.NextProtos[0] = "http/1.1"
				} else {
					tlsConfig.NextProtos = nil
				}
			}
			conn = tls.Client(conn, tlsConfig)
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
