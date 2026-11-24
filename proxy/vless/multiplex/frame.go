package multiplex

import (
	"encoding/binary"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/bitmask"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/xudp"
)

type SessionStatus byte

const (
	SessionStatusNew       SessionStatus = 0x01
	SessionStatusKeep      SessionStatus = 0x02
	SessionStatusEnd       SessionStatus = 0x03
	SessionStatusKeepAlive SessionStatus = 0x04
)

const (
	OptionData  bitmask.Byte = 0x01
	OptionError bitmask.Byte = 0x02
)

type TargetNetwork byte

const (
	TargetNetworkTCP TargetNetwork = 0x01
	TargetNetworkUDP TargetNetwork = 0x02
)

var addrParser = xudp.AddrParser

/*
Frame format
2 bytes - length
2 bytes - session id
1 bytes - status
1 bytes - option

1 byte - network
2 bytes - port
n bytes - address

*/

type FrameMetadata struct {
	Target        net.Destination
	SessionID     uint16
	Option        bitmask.Byte
	SessionStatus SessionStatus
	GlobalID      [8]byte
	Inbound       *session.Inbound
}

func (f FrameMetadata) WriteTo(b *buf.Buffer) error {
	lenBytes := b.Extend(2)

	len0 := b.Len()
	sessionBytes := b.Extend(2)
	binary.BigEndian.PutUint16(sessionBytes, f.SessionID)

	common.Must(b.WriteByte(byte(f.SessionStatus)))
	common.Must(b.WriteByte(byte(f.Option)))

	if f.SessionStatus == SessionStatusNew {
		switch f.Target.Network {
		case net.Network_TCP:
			common.Must(b.WriteByte(byte(TargetNetworkTCP)))
		case net.Network_UDP:
			common.Must(b.WriteByte(byte(TargetNetworkUDP)))
		}
		if err := addrParser.WriteAddressPort(b, f.Target.Address, f.Target.Port); err != nil {
			return err
		}
		if f.Inbound != nil {
			for _, dst := range [...]net.Destination{f.Inbound.Source, f.Inbound.Local} {
				if dst.Network != net.Network_TCP && dst.Network != net.Network_UDP {
					break
				}
				common.Must(b.WriteByte(byte(dst.Network - 1)))
				if err := addrParser.WriteAddressPort(b, dst.Address, dst.Port); err != nil {
					return err
				}
			}
		} else if b.UDP != nil { // make sure it's user's proxy request
			b.Write(f.GlobalID[:]) // no need to check whether it's empty
		}
	} else if b.UDP != nil {
		b.WriteByte(byte(TargetNetworkUDP))
		addrParser.WriteAddressPort(b, b.UDP.Address, b.UDP.Port)
	}

	len1 := b.Len()
	binary.BigEndian.PutUint16(lenBytes, uint16(len1-len0))
	return nil
}

// Unmarshal reads FrameMetadata from the given reader.
func (f *FrameMetadata) Unmarshal(reader io.Reader, readSourceAndLocal bool) error {
	b, err := readBlock(reader, 512, "invalid metalen ")
	if err != nil {
		return err
	}
	defer b.Release()
	return frameReadError(f.UnmarshalFromBuffer(b, readSourceAndLocal))
}

// UnmarshalFromBuffer reads a FrameMetadata from the given buffer.
// Visible for testing only.
func (f *FrameMetadata) UnmarshalFromBuffer(b *buf.Buffer, readSourceAndLocal bool) error {
	if b.Len() < 4 {
		return errors.New("insufficient buffer: ", b.Len())
	}

	f.SessionID = binary.BigEndian.Uint16(b.BytesTo(2))
	f.SessionStatus = SessionStatus(b.Byte(2))
	f.Option = bitmask.Byte(b.Byte(3))
	f.Target.Network = net.Network_Unknown

	if f.SessionStatus == SessionStatusNew || (f.SessionStatus == SessionStatusKeep && b.Len() > 4 &&
		TargetNetwork(b.Byte(4)) == TargetNetworkUDP) { // MUST check the flag first
		if b.Len() < 8 {
			return errors.New("insufficient buffer: ", b.Len())
		}
		b.Advance(4)
		target, err := readDestination(b, "")
		if err != nil {
			return err
		}
		f.Target = target
	}

	if f.SessionStatus == SessionStatusNew && readSourceAndLocal {
		f.Inbound = &session.Inbound{}
		for i, dst := range [...]*net.Destination{&f.Inbound.Source, &f.Inbound.Local} {
			if b.Len() == 0 || b.Byte(0) == 0 { // heartbeat, absent endpoint, or padding
				break
			}
			parsed, err := readDestination(b, [...]string{"reading source: ", "reading local: "}[i])
			if err != nil {
				return err
			}
			*dst = parsed
		}
		return nil
	}

	if f.SessionStatus == SessionStatusNew && f.Option.Has(OptionData) &&
		f.Target.Network == net.Network_UDP && b.Len() >= 8 {
		copy(f.GlobalID[:], b.Bytes())
	}

	return nil
}

func readDestination(b *buf.Buffer, prefix string) (net.Destination, error) {
	network := TargetNetwork(b.Byte(0))
	b.Advance(1)
	addr, port, err := addrParser.ReadAddressPort(nil, b)
	if err != nil {
		return net.Destination{}, errors.New(prefix, "failed to parse address and port").Base(err)
	}
	switch network {
	case TargetNetworkTCP:
		return net.TCPDestination(addr, port), nil
	case TargetNetworkUDP:
		return net.UDPDestination(addr, port), nil
	default:
		return net.Destination{}, errors.New(prefix, "unknown network type: ", network)
	}
}
