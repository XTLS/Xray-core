package protocol

import (
	"runtime"

	"github.com/xtls/xray-core/common/bitmask"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/uuid"
	"golang.org/x/sys/cpu"
)

// RequestCommand is a custom command in a proxy request.
type RequestCommand byte

const (
	RequestCommandTCP = RequestCommand(0x01)
	RequestCommandUDP = RequestCommand(0x02)
	RequestCommandMux = RequestCommand(0x03)
)

func (c RequestCommand) TransferType() TransferType {
	switch c {
	case RequestCommandTCP, RequestCommandMux:
		return TransferTypeStream
	case RequestCommandUDP:
		return TransferTypePacket
	default:
		return TransferTypeStream
	}
}

const (
	// [DEPRECATED 2023-06] RequestOptionChunkStream indicates request payload is chunked. Each chunk consists of length, authentication and payload.
	RequestOptionChunkStream bitmask.Byte = 0x01

	// 0x02 legacy setting

	RequestOptionChunkMasking bitmask.Byte = 0x04

	RequestOptionGlobalPadding bitmask.Byte = 0x08

	RequestOptionAuthenticatedLength bitmask.Byte = 0x10
)

type RequestHeader struct {
	Version  byte
	Command  RequestCommand
	Option   bitmask.Byte
	Security SecurityType
	Port     net.Port
	Address  net.Address
	User     *MemoryUser
}

func (h *RequestHeader) Destination() net.Destination {
	if h.Command == RequestCommandUDP {
		return net.UDPDestination(h.Address, h.Port)
	}
	return net.TCPDestination(h.Address, h.Port)
}

const (
	ResponseOptionConnectionReuse bitmask.Byte = 0x01
)

type ResponseCommand interface{}

type ResponseHeader struct {
	Option  bitmask.Byte
	Command ResponseCommand
}

type CommandSwitchAccount struct {
	Host     net.Address
	Port     net.Port
	ID       uuid.UUID
	Level    uint32
	ValidMin byte
}

var (
	hasGCMAsmAMD64 = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ
	hasGCMAsmARM64 = cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
	// Keep in sync with crypto/aes/cipher_s390x.go.
	hasGCMAsmS390X = cpu.S390X.HasAES && cpu.S390X.HasAESCBC && cpu.S390X.HasAESCTR &&
		(cpu.S390X.HasGHASH || cpu.S390X.HasAESGCM)

	hasAESGCMHardwareSupport = runtime.GOARCH == "amd64" && hasGCMAsmAMD64 ||
		runtime.GOARCH == "arm64" && hasGCMAsmARM64 ||
		runtime.GOARCH == "s390x" && hasGCMAsmS390X
)

func (sc *SecurityConfig) GetSecurityType() SecurityType {
	if sc == nil || sc.Type == SecurityType_AUTO {
		if hasAESGCMHardwareSupport {
			return SecurityType_AES128_GCM
		}
		return SecurityType_CHACHA20_POLY1305
	}
	return sc.Type
}

func isDomainTooLong(domain string) bool {
	return len(domain) > 256
}
