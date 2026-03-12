/**
 * Author: Mundo
 * Date: 12/03/26
 * Description: ECH wrapper for TLS handshake
 */
package ech

import (
	"context"
	gotls "crypto/tls"
	stderrors "errors"
	"net"

	quic "github.com/apernet/quic-go"
	utls "github.com/refraction-networking/utls"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

type DialFacility func(ctx context.Context) (net.Conn, error)

type QUICDialFacility func(ctx context.Context, cfg *gotls.Config) (*quic.Conn, error)

func UHandshake(
	ctx context.Context,
	dialFn DialFacility,
	cfg *gotls.Config,
	fingerprint *utls.ClientHelloID,
	websocket bool,
) (*xtls.UConn, error) {
	conn, err := uDo(ctx, dialFn, cfg, fingerprint, websocket)
	if err == nil {
		return conn, nil
	}

	var echErr *utls.ECHRejectionError
	if stderrors.As(err, &echErr) && len(echErr.RetryConfigList) > 0 {
		retry := cfg.Clone()
		retry.EncryptedClientHelloConfigList = echErr.RetryConfigList

		conn, retryErr := uDo(ctx, dialFn, retry, fingerprint, websocket)
		if retryErr != nil {
			return nil, retryErr
		}

		xtls.StoreRecentECH(cfg.ServerName, echErr.RetryConfigList)
		return conn, nil
	}

	return nil, err
}

func StdHandshake(
	ctx context.Context,
	dialFn DialFacility,
	cfg *gotls.Config,
) (*xtls.Conn, error) {
	conn, err := stdDo(ctx, dialFn, cfg)
	if err == nil {
		return conn, nil
	}

	var echErr *gotls.ECHRejectionError
	if stderrors.As(err, &echErr) && len(echErr.RetryConfigList) > 0 {
		retry := cfg.Clone()
		retry.EncryptedClientHelloConfigList = echErr.RetryConfigList

		conn, retryErr := stdDo(ctx, dialFn, retry)
		if retryErr != nil {
			return nil, retryErr
		}

		xtls.StoreRecentECH(cfg.ServerName, echErr.RetryConfigList)
		return conn, nil
	}

	return nil, err
}

func QUICHandshake(
	ctx context.Context,
	quicDialFn QUICDialFacility,
	cfg *gotls.Config,
) (*quic.Conn, error) {
	conn, err := quicDialFn(ctx, cfg)
	if err == nil {
		return conn, nil
	}

	var echErr *gotls.ECHRejectionError
	if stderrors.As(err, &echErr) && len(echErr.RetryConfigList) > 0 {
		retry := cfg.Clone()
		retry.EncryptedClientHelloConfigList = echErr.RetryConfigList

		conn, retryErr := quicDialFn(ctx, retry)
		if retryErr != nil {
			return nil, retryErr
		}

		xtls.StoreRecentECH(cfg.ServerName, echErr.RetryConfigList)
		return conn, nil
	}

	return nil, err
}

func uDo(
	ctx context.Context,
	dialFn DialFacility,
	cfg *gotls.Config,
	fingerprint *utls.ClientHelloID,
	websocket bool,
) (*xtls.UConn, error) {
	raw, err := dialFn(ctx)
	if err != nil {
		return nil, err
	}
	uconn := xtls.UClient(raw, cfg, fingerprint).(*xtls.UConn)
	if websocket {
		err = uconn.WebsocketHandshakeContext(ctx)
	} else {
		err = uconn.HandshakeContext(ctx)
	}
	if err != nil {
		raw.Close()
		return nil, err
	}
	return uconn, nil
}

func stdDo(
	ctx context.Context,
	dialFn DialFacility,
	cfg *gotls.Config,
) (*xtls.Conn, error) {
	raw, err := dialFn(ctx)
	if err != nil {
		return nil, err
	}
	conn := xtls.Client(raw, cfg).(*xtls.Conn)
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}
