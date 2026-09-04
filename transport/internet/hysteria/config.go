package hysteria

import (
	"context"
	"math/rand"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/transport/internet"
)

const (
	closeErrCodeOK            = 0x100 // HTTP3 ErrCodeNoError
	closeErrCodeProtocolError = 0x101 // HTTP3 ErrCodeGeneralProtocolError
	URLHost                   = "hysteria"
	URLPath                   = "/auth"
	RequestHeaderAuth         = "Hysteria-Auth"
	ResponseHeaderUDPEnabled  = "Hysteria-UDP"
	CommonHeaderCCRX          = "Hysteria-CC-RX"
	CommonHeaderPadding       = "Hysteria-Padding"
	StatusAuthOK              = 233
	FrameTypeTCPRequest       = 0x401
	MaxDatagramFrameSize      = 1200
	udpMessageChanSize        = 1024
	idleCleanupInterval       = 1 * time.Second
)

const (
	paddingChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

type padding struct {
	Min int
	Max int
}

func (p padding) String() string {
	n := p.Min + rand.Intn(p.Max-p.Min)
	bs := make([]byte, n)
	for i := range bs {
		bs[i] = paddingChars[rand.Intn(len(paddingChars))]
	}
	return string(bs)
}

var (
	AuthRequestPadding  = padding{Min: 256, Max: 2048}
	AuthResponsePadding = padding{Min: 256, Max: 2048}
	TcpRequestPadding   = padding{Min: 64, Max: 512}
	TcpResponsePadding  = padding{Min: 128, Max: 1024}
)

type datagramKey struct{}

func ContextWithDatagram(ctx context.Context, v bool) context.Context {
	return context.WithValue(ctx, datagramKey{}, v)
}

func DatagramFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(datagramKey{}).(bool)
	return v
}

type validatorKey struct{}

func ContextWithValidator(ctx context.Context, v *account.Validator) context.Context {
	return context.WithValue(ctx, validatorKey{}, v)
}

func ValidatorFromContext(ctx context.Context) *account.Validator {
	v, _ := ctx.Value(validatorKey{}).(*account.Validator)
	return v
}

type status int

const (
	StatusNull status = iota
	StatusActive
	StatusInactive
)

const protocolName = "hysteria"

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return &Config{
			UdpIdleTimeout: 60,
		}
	}))
}
