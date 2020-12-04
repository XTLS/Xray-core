package utp

import (
	"context"
	"encoding/binary"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/dice"
)

type UTP struct {
	header       byte
	extension    byte
	connectionID uint16
}

func (*UTP) Size() int32 {
	return 4
}

// Serialize implements PacketHeader.
func (u *UTP) Serialize(b []byte) {
	binary.BigEndian.PutUint16(b, u.connectionID)
	b[2] = u.header
	b[3] = u.extension
}

// New creates a new UTP header for the given config.
func New(ctx context.Context, config interface{}) (interface{}, error) {
	return &UTP{
		header:       1,
		extension:    0,
		connectionID: dice.RollUint16(),
	}, nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), New))
}
