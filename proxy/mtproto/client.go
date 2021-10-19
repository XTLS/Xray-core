package mtproto

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type Client struct{}

func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	return &Client{}, nil
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("unknown destination.")
	}
	dest := outbound.Target
	if dest.Network != net.Network_TCP {
		return newError("not TCP traffic", dest)
	}

	conn, err := dialer.Dial(ctx, dest)
	if err != nil {
		return newError("failed to dial to ", dest).Base(err).AtWarning()
	}
	defer conn.Close()

	sc := SessionContextFromContext(ctx)
	auth := NewAuthentication(sc)
	defer putAuthenticationObject(auth)

	request := func() error {
		encryptor := crypto.NewAesCTRStream(auth.EncodingKey[:], auth.EncodingNonce[:])

		var header [HeaderSize]byte
		encryptor.XORKeyStream(header[:], auth.Header[:])
		copy(header[:56], auth.Header[:])

		if _, err := conn.Write(header[:]); err != nil {
			return newError("failed to write auth header").Base(err)
		}

		connWriter := buf.NewWriter(crypto.NewCryptionWriter(encryptor, conn))
		return buf.Copy(link.Reader, connWriter)
	}

	response := func() error {
		decryptor := crypto.NewAesCTRStream(auth.DecodingKey[:], auth.DecodingNonce[:])

		connReader := buf.NewReader(crypto.NewCryptionReader(decryptor, conn))
		return buf.Copy(connReader, link.Writer)
	}

	responseDoneAndCloseWriter := task.OnSuccess(response, task.Close(link.Writer))
	if err := task.Run(ctx, request, responseDoneAndCloseWriter); err != nil {
		return newError("connection ends").Base(err)
	}

	return nil
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}
