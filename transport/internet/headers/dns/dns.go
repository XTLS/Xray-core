package dns

import (
	"context"
	"encoding/binary"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/dice"
)

type DNS struct {
	header []byte
}

func (d DNS) Size() int32 {
	return int32(len(d.header))
}

// Serialize implements PacketHeader.
func (d DNS) Serialize(b []byte) {
	copy(b, d.header)
	binary.BigEndian.PutUint16(b[0:], dice.RollUint16()) // random transaction ID
}

// NewDNS returns a new DNS instance based on given config.
func NewDNS(ctx context.Context, config interface{}) (interface{}, error) {
	var header []byte

	header = binary.BigEndian.AppendUint16(header, 0x0000) // Transaction ID
	header = binary.BigEndian.AppendUint16(header, 0x0100) // Flags: Standard query
	header = binary.BigEndian.AppendUint16(header, 0x0001) // Questions
	header = binary.BigEndian.AppendUint16(header, 0x0000) // Answer RRs
	header = binary.BigEndian.AppendUint16(header, 0x0000) // Authority RRs
	header = binary.BigEndian.AppendUint16(header, 0x0000) // Additional RRs

	buf := make([]byte, 0x100)

	off1, err := dns.PackDomainName(dns.Fqdn(config.(*Config).Domain), buf, 0, nil, false)
	if err != nil {
		return nil, err
	}

	header = append(header, buf[:off1]...)

	header = binary.BigEndian.AppendUint16(header, 0x0001) // Type: A
	header = binary.BigEndian.AppendUint16(header, 0x0001) // Class: IN

	return DNS{
		header: header,
	}, nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), NewDNS))
}
