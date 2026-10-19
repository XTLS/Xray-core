package tls

import (
	"encoding/binary"
	"errors"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
)

type SniffHeader struct {
	domain string
}

func (h *SniffHeader) Protocol() string {
	return "tls"
}

func (h *SniffHeader) Domain() string {
	return h.domain
}

var (
	errNotTLS         = errors.New("not TLS header")
	errNotClientHello = errors.New("not client hello")
)

func IsValidTLSVersion(major, minor byte) bool {
	return major == 3
}

// ReadClientHello returns server name (if any) from TLS client hello message.
// https://github.com/golang/go/blob/master/src/crypto/tls/handshake_messages.go#L300
func ReadClientHello(data []byte, h *SniffHeader) error {
	if len(data) < 42 {
		return common.ErrNoClue
	}
	sessionIDLen := int(data[38])
	if sessionIDLen > 32 || len(data) < 39+sessionIDLen {
		return common.ErrNoClue
	}
	data = data[39+sessionIDLen:]
	if len(data) < 2 {
		return common.ErrNoClue
	}
	// cipherSuiteLen is the number of bytes of cipher suite numbers. Since
	// they are uint16s, the number must be even.
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return errNotClientHello
	}
	data = data[2+cipherSuiteLen:]
	if len(data) < 1 {
		return common.ErrNoClue
	}
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return common.ErrNoClue
	}
	data = data[1+compressionMethodsLen:]

	if len(data) < 2 {
		return errNotClientHello
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		return errNotClientHello
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return errNotClientHello
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return errNotClientHello
		}

		if extension == 0x00 { /* extensionServerName */
			d := data[:length]
			if len(d) < 2 {
				return errNotClientHello
			}
			namesLen := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if len(d) != namesLen {
				return errNotClientHello
			}
			for len(d) > 0 {
				if len(d) < 3 {
					return errNotClientHello
				}
				nameType := d[0]
				nameLen := int(d[1])<<8 | int(d[2])
				d = d[3:]
				if len(d) < nameLen {
					return errNotClientHello
				}
				if nameType == 0 {
					// QUIC separated across packets
					// May cause the serverName to be incomplete
					b := byte(0)
					for _, b = range d[:nameLen] {
						if b <= ' ' {
							return protocol.ErrProtoNeedMoreData
						}
					}
					// An SNI value may not include a
					// trailing dot. See
					// https://tools.ietf.org/html/rfc6066#section-3.
					if b == '.' {
						return errNotClientHello
					}
					serverName := string(d[:nameLen])
					h.domain = serverName
					return nil
				}
				d = d[nameLen:]
			}
		}
		data = data[length:]
	}

	return errNotTLS
}

func SniffTLS(b []byte) (*SniffHeader, error) {
	if len(b) == 0 {
		return nil, common.ErrNoClue
	}
	if b[0] != 0x16 /* TLS Handshake */ {
		return nil, errNotTLS
	}

	// A ClientHello can span both reads and TLS records. Allocate only for bytes
	// actually received, never for the length advertised by the peer.
	var hello []byte
	for {
		if len(b) < 5 {
			return nil, protocol.ErrProtoNeedMoreData
		}
		if b[0] != 0x16 || !IsValidTLSVersion(b[1], b[2]) {
			return nil, errNotTLS
		}
		recordLen := int(binary.BigEndian.Uint16(b[3:5]))
		if recordLen == 0 || recordLen > 16384 {
			return nil, errNotClientHello
		}
		if len(b) < 5+recordLen {
			return nil, protocol.ErrProtoNeedMoreData
		}
		record := b[5 : 5+recordLen]
		if hello == nil {
			hello = record[:len(record):len(record)]
		} else {
			hello = append(hello, record...)
		}
		if hello[0] != 1 { // ClientHello
			return nil, errNotClientHello
		}
		if len(hello) >= 4 {
			helloLen := 4 + (int(hello[1]) << 16) + (int(hello[2]) << 8) + int(hello[3])
			if len(hello) >= helloLen {
				h := &SniffHeader{}
				err := ReadClientHello(hello[:helloLen], h)
				if err == nil {
					return h, nil
				}
				// The full handshake is present: shortages inside it are malformed,
				// unlike QUIC's potentially sparse input to ReadClientHello.
				if err == common.ErrNoClue || err == protocol.ErrProtoNeedMoreData {
					err = errNotClientHello
				}
				return nil, err
			}
		}
		b = b[5+recordLen:]
		if len(b) == 0 {
			return nil, protocol.ErrProtoNeedMoreData
		}
	}
}
