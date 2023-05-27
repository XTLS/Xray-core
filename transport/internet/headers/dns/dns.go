package dns

import (
	"context"
	"encoding/binary"
	"errors"

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

	off1, err := packDomainName(config.(*Config).Domain + ".", buf)
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

// copied from github.com/miekg/dns
func packDomainName(s string, msg []byte) (off1 int, err error) {
	off := 0
	ls := len(s)
	// Each dot ends a segment of the name.
	// We trade each dot byte for a length byte.
	// Except for escaped dots (\.), which are normal dots.
	// There is also a trailing zero.

	// Emit sequence of counted strings, chopping at dots.
	var (
		begin     int
		bs        []byte
	)
	for i := 0; i < ls; i++ {
		var c byte
		if bs == nil {
			c = s[i]
		} else {
			c = bs[i]
		}

		switch c {
		case '\\':
			if off+1 > len(msg) {
				return len(msg), errors.New("buffer size too small")
			}

			if bs == nil {
				bs = []byte(s)
			}

			copy(bs[i:ls-1], bs[i+1:])
			ls--
		case '.':
			labelLen := i - begin
			if labelLen >= 1<<6 { // top two bits of length must be clear
				return len(msg), errors.New("bad rdata")
			}

			// off can already (we're in a loop) be bigger than len(msg)
			// this happens when a name isn't fully qualified
			if off+1+labelLen > len(msg) {
				return len(msg), errors.New("buffer size too small")
			}

			// The following is covered by the length check above.
			msg[off] = byte(labelLen)

			if bs == nil {
				copy(msg[off+1:], s[begin:i])
			} else {
				copy(msg[off+1:], bs[begin:i])
			}
			off += 1 + labelLen
			begin = i + 1
		default:
		}
	}

	if off < len(msg) {
		msg[off] = 0
	}

	return off + 1, nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), NewDNS))
}
