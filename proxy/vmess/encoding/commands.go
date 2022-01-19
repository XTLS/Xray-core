package encoding

import (
	"encoding/binary"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
)

var (
	ErrCommandTooLarge     = newError("Command too large.")
	ErrCommandTypeMismatch = newError("Command type mismatch.")
	ErrInvalidAuth         = newError("Invalid auth.")
	ErrInsufficientLength  = newError("Insufficient length.")
	ErrUnknownCommand      = newError("Unknown command.")
)

func MarshalCommand(command interface{}, writer io.Writer) error {
	if command == nil {
		return ErrUnknownCommand
	}

	var cmdID byte
	var factory CommandFactory
	switch command.(type) {
	case *protocol.CommandSwitchAccount:
		factory = new(CommandSwitchAccountFactory)
		cmdID = 1
	default:
		return ErrUnknownCommand
	}

	buffer := buf.New()
	defer buffer.Release()

	err := factory.Marshal(command, buffer)
	if err != nil {
		return err
	}

	auth := Authenticate(buffer.Bytes())
	length := buffer.Len() + 4
	if length > 255 {
		return ErrCommandTooLarge
	}

	common.Must2(writer.Write([]byte{cmdID, byte(length), byte(auth >> 24), byte(auth >> 16), byte(auth >> 8), byte(auth)}))
	common.Must2(writer.Write(buffer.Bytes()))
	return nil
}

func UnmarshalCommand(cmdID byte, data []byte) (protocol.ResponseCommand, error) {
	if len(data) <= 4 {
		return nil, ErrInsufficientLength
	}
	expectedAuth := Authenticate(data[4:])
	actualAuth := binary.BigEndian.Uint32(data[:4])
	if expectedAuth != actualAuth {
		return nil, ErrInvalidAuth
	}

	var factory CommandFactory
	switch cmdID {
	case 1:
		factory = new(CommandSwitchAccountFactory)
	default:
		return nil, ErrUnknownCommand
	}
	return factory.Unmarshal(data[4:])
}

type CommandFactory interface {
	Marshal(command interface{}, writer io.Writer) error
	Unmarshal(data []byte) (interface{}, error)
}

type CommandSwitchAccountFactory struct{}

func (f *CommandSwitchAccountFactory) Marshal(command interface{}, writer io.Writer) error {
	cmd, ok := command.(*protocol.CommandSwitchAccount)
	if !ok {
		return ErrCommandTypeMismatch
	}

	hostStr := ""
	if cmd.Host != nil {
		hostStr = cmd.Host.String()
	}
	common.Must2(writer.Write([]byte{byte(len(hostStr))}))

	if len(hostStr) > 0 {
		common.Must2(writer.Write([]byte(hostStr)))
	}

	common.Must2(serial.WriteUint16(writer, cmd.Port.Value()))

	idBytes := cmd.ID.Bytes()
	common.Must2(writer.Write(idBytes))
	common.Must2(serial.WriteUint16(writer, cmd.AlterIds))
	common.Must2(writer.Write([]byte{byte(cmd.Level)}))

	common.Must2(writer.Write([]byte{cmd.ValidMin}))
	return nil
}

func (f *CommandSwitchAccountFactory) Unmarshal(data []byte) (interface{}, error) {
	cmd := new(protocol.CommandSwitchAccount)
	if len(data) == 0 {
		return nil, ErrInsufficientLength
	}
	lenHost := int(data[0])
	if len(data) < lenHost+1 {
		return nil, ErrInsufficientLength
	}
	if lenHost > 0 {
		cmd.Host = net.ParseAddress(string(data[1 : 1+lenHost]))
	}
	portStart := 1 + lenHost
	if len(data) < portStart+2 {
		return nil, ErrInsufficientLength
	}
	cmd.Port = net.PortFromBytes(data[portStart : portStart+2])
	idStart := portStart + 2
	if len(data) < idStart+16 {
		return nil, ErrInsufficientLength
	}
	cmd.ID, _ = uuid.ParseBytes(data[idStart : idStart+16])
	alterIDStart := idStart + 16
	if len(data) < alterIDStart+2 {
		return nil, ErrInsufficientLength
	}
	cmd.AlterIds = binary.BigEndian.Uint16(data[alterIDStart : alterIDStart+2])
	levelStart := alterIDStart + 2
	if len(data) < levelStart+1 {
		return nil, ErrInsufficientLength
	}
	cmd.Level = uint32(data[levelStart])
	timeStart := levelStart + 1
	if len(data) < timeStart+1 {
		return nil, ErrInsufficientLength
	}
	cmd.ValidMin = data[timeStart]
	return cmd, nil
}
