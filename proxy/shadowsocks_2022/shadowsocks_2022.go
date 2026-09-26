package shadowsocks_2022

import (
	"context"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport"
)

type udpConnEntry struct {
	sync.Mutex
	link   *transport.Link
	timer  *signal.ActivityTimer
	cancel context.CancelFunc
}

const (
	HeaderTypeClient              = 0
	HeaderTypeServer              = 1
	MaxPaddingLength              = 900
	PacketNonceSize               = 24
	MaxPacketSize                 = 65535
	RequestHeaderFixedChunkLength = 1 + 8 + 2 // Type (1B) + Timestamp (8B) + VarHeaderLen (2B)
	PacketMinimalHeaderSize       = 30
	StreamNonceSize               = 12
	AESBlockSize                  = 16
	AEADTagSize                   = 16
)

var zeroPadding [MaxPaddingLength]byte

const (
	MethodAES128GCM        = "2022-blake3-aes-128-gcm"
	MethodAES256GCM        = "2022-blake3-aes-256-gcm"
	MethodChaCha20Poly1305 = "2022-blake3-chacha20-poly1305"
)

var (
	ErrBadKey            = errors.New("bad key")
	ErrBadHeaderType     = errors.New("bad header type")
	ErrBadTimestamp      = errors.New("bad timestamp")
	ErrSaltNotUnique     = errors.New("salt not unique")
	ErrPacketIdNotUnique = errors.New("packet id not unique")
	ErrPacketTooShort    = errors.New("packet too short")
	ErrPacketTooLarge    = errors.New("packet too large")
	ErrNoPadding         = errors.New("bad request: missing payload or padding")
	ErrInvalidRequest    = errors.New("invalid request")
)
