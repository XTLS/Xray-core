package xudp

import (
	"io"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

var addrParser = protocol.NewAddressParser(
	protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv4), net.AddressFamilyIPv4),
	protocol.AddressFamilyByte(byte(protocol.AddressTypeDomain), net.AddressFamilyDomain),
	protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv6), net.AddressFamilyIPv6),
	protocol.PortThenAddress(),
)

func NewPacketWriter(writer buf.Writer, dest net.Destination) *PacketWriter {
	return &PacketWriter{
		Writer: writer,
		Dest:   dest,
	}
}

type PacketWriter struct {
	Writer buf.Writer
	Dest   net.Destination
}

func (w *PacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	mb2Write := make(buf.MultiBuffer, 0, len(mb))
	for _, b := range mb {
		length := b.Len()
		if length == 0 || length+666 > buf.Size {
			continue
		}

		eb := buf.New()
		eb.Write([]byte{0, 0, 0, 0})
		if w.Dest.Network == net.Network_UDP {
			eb.WriteByte(1) // New
			eb.WriteByte(1) // Opt
			eb.WriteByte(2) // UDP
			addrParser.WriteAddressPort(eb, w.Dest.Address, w.Dest.Port)
			w.Dest.Network = net.Network_Unknown
		} else {
			eb.WriteByte(2) // Keep
			eb.WriteByte(1)
			if b.UDP != nil {
				eb.WriteByte(2)
				addrParser.WriteAddressPort(eb, b.UDP.Address, b.UDP.Port)
			}
		}
		l := eb.Len() - 2
		eb.SetByte(0, byte(l>>8))
		eb.SetByte(1, byte(l))
		eb.WriteByte(byte(length >> 8))
		eb.WriteByte(byte(length))
		eb.Write(b.Bytes())

		mb2Write = append(mb2Write, eb)
	}
	if mb2Write.IsEmpty() {
		return nil
	}
	return w.Writer.WriteMultiBuffer(mb2Write)
}

func NewPacketReader(reader io.Reader) *PacketReader {
	return &PacketReader{
		Reader: reader,
		cache:  make([]byte, 2),
	}
}

type PacketReader struct {
	Reader io.Reader
	cache  []byte
}

func (r *PacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	for {
		if _, err := io.ReadFull(r.Reader, r.cache); err != nil {
			return nil, err
		}
		l := int32(r.cache[0])<<8 | int32(r.cache[1])
		if l < 4 {
			return nil, io.EOF
		}
		b := buf.New()
		if _, err := b.ReadFullFrom(r.Reader, l); err != nil {
			b.Release()
			return nil, err
		}
		discard := false
		switch b.Byte(2) {
		case 2:
			if l != 4 {
				b.Advance(5)
				addr, port, err := addrParser.ReadAddressPort(nil, b)
				if err != nil {
					b.Release()
					return nil, err
				}
				b.UDP = &net.Destination{
					Network: net.Network_UDP,
					Address: addr,
					Port:    port,
				}
			}
		case 4:
			discard = true
		default:
			b.Release()
			return nil, io.EOF
		}
		if b.Byte(3) == 1 {
			if _, err := io.ReadFull(r.Reader, r.cache); err != nil {
				b.Release()
				return nil, err
			}
			length := int32(r.cache[0])<<8 | int32(r.cache[1])
			if length > 0 {
				b.Clear()
				if _, err := b.ReadFullFrom(r.Reader, length); err != nil {
					b.Release()
					return nil, err
				}
				if !discard {
					return buf.MultiBuffer{b}, nil
				}
			}
		}
		b.Release()
	}
}
