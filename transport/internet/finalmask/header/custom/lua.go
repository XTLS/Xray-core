package custom

import (
	"crypto/rand"
	"io"
	"net"
	"time"

	"github.com/xtls/xray-core/common/errors"
	xlua "github.com/xtls/xray-core/common/lua"
	"github.com/xtls/xray-core/transport/internet/finalmask/noise"
	lua "github.com/yuin/gopher-lua"
)

const (
	valueLimit  = 65535
	streamLimit = 65535
	headerLimit = 1024
)

const streamKey = "xray.finalmask.header.stream"

type headerStream struct {
	conn    net.Conn
	written int
	read    int
	open    bool
}

func RegisterLua(L *lua.LState) {
	noise.RegisterLua(L)
}

func registerStream(L *lua.LState) {
	meta := L.CreateTable(0, 4)
	meta.RawSetString("__index", meta)
	meta.RawSetString("Write", L.NewFunction(streamWrite))
	meta.RawSetString("Read", L.NewFunction(streamRead))
	meta.RawSetString("Sleep", L.NewFunction(streamSleep))

	data := L.NewUserData()
	data.Value = &headerStream{}
	data.Metatable = meta
	L.SetField(L.G.Registry, streamKey, data)
}

func streamWrite(L *lua.LState) int {
	packet, ok := L.Get(2).(lua.LString)
	if !ok {
		L.RaiseError("Write requires a packet string")
		return 0
	}
	stream := streamFor(L, len(packet))
	if _, err := stream.conn.Write([]byte(packet)); err != nil {
		L.RaiseError("Write failed: %v", err)
		return 0
	}
	stream.written += len(packet)
	return 0
}

func streamRead(L *lua.LState) int {
	size := L.CheckNumber(2)
	if !(size >= 1 && size <= valueLimit) {
		L.RaiseError("Read requires a size of 1 to %d", valueLimit)
		return 0
	}
	stream := streamFor(L, 0)
	if stream.read+int(size) > streamLimit {
		L.RaiseError("the handshake reads at most %d bytes", streamLimit)
		return 0
	}
	buf := make([]byte, int(size))
	if _, err := io.ReadFull(stream.conn, buf); err != nil {
		L.RaiseError("Read failed: %v", err)
		return 0
	}
	stream.read += len(buf)
	xlua.PushString(L, string(buf))
	return 1
}

func streamSleep(L *lua.LState) int {
	delay := L.CheckNumber(2)
	if !(delay >= 0 && delay <= valueLimit) {
		L.RaiseError("Sleep requires a delay of 0 to %d milliseconds", valueLimit)
		return 0
	}
	streamFor(L, 0)
	time.Sleep(time.Duration(delay) * time.Millisecond)
	return 0
}

func streamFor(L *lua.LState, write int) *headerStream {
	stream, err := xlua.ReadUserData[*headerStream](L.Get(1), "the stream the Hook was given is missing")
	if err != nil {
		L.RaiseError("%s", err.Error())
		return nil
	}
	if !stream.open {
		L.RaiseError("the stream only works while the Hook runs")
		return nil
	}
	if stream.written+write > streamLimit {
		L.RaiseError("the handshake writes at most %d bytes", streamLimit)
		return nil
	}
	return stream
}

func luaStream(L *lua.LState) (*lua.LUserData, *headerStream, error) {
	data, ok := L.GetField(L.G.Registry, streamKey).(*lua.LUserData)
	if !ok {
		return nil, nil, errors.New("header script has no stream")
	}
	stream, ok := data.Value.(*headerStream)
	if !ok {
		return nil, nil, errors.New("header script has no stream")
	}
	return data, stream, nil
}

const (
	headerKey = "xray.finalmask.header.builder"
	packetKey = "xray.finalmask.header.packet"
)

type headerBuilder struct {
	bytes []byte
	open  bool
}

type headerPacket struct {
	data []byte
	open bool
}

func registerPacketHooks(L *lua.LState) {
	builderMeta := L.CreateTable(0, 3)
	builderMeta.RawSetString("__index", builderMeta)
	builderMeta.RawSetString("Add", L.NewFunction(builderAdd))
	builderMeta.RawSetString("AddRandom", L.NewFunction(builderAddRandom))

	builder := L.NewUserData()
	builder.Value = &headerBuilder{}
	builder.Metatable = builderMeta
	L.SetField(L.G.Registry, headerKey, builder)

	packetMeta := L.CreateTable(0, 5)
	packetMeta.RawSetString("__index", packetMeta)
	packetMeta.RawSetString("Len", L.NewFunction(packetLen))
	packetMeta.RawSetString("Byte", L.NewFunction(packetByte))
	packetMeta.RawSetString("Match", L.NewFunction(packetMatch))
	packetMeta.RawSetString("Slice", L.NewFunction(packetSlice))

	packet := L.NewUserData()
	packet.Value = &headerPacket{}
	packet.Metatable = packetMeta
	L.SetField(L.G.Registry, packetKey, packet)
}

func builderAdd(L *lua.LState) int {
	bytes, ok := L.Get(2).(lua.LString)
	if !ok {
		L.RaiseError("Add requires a string")
		return 0
	}
	builder := builderFor(L, len(bytes))
	builder.bytes = append(builder.bytes, bytes...)
	return 0
}

func builderAddRandom(L *lua.LState) int {
	size := L.CheckNumber(2)
	if !(size >= 0 && size <= headerLimit) {
		L.RaiseError("AddRandom requires a size of 0 to %d", headerLimit)
		return 0
	}
	builder := builderFor(L, int(size))
	at := len(builder.bytes)
	builder.bytes = append(builder.bytes, make([]byte, int(size))...)
	if _, err := rand.Read(builder.bytes[at:]); err != nil {
		L.RaiseError("AddRandom failed: %v", err)
		return 0
	}
	return 0
}

func builderFor(L *lua.LState, add int) *headerBuilder {
	builder, err := xlua.ReadUserData[*headerBuilder](L.Get(1), "the header the Hook was given is missing")
	if err != nil {
		L.RaiseError("%s", err.Error())
		return nil
	}
	if !builder.open {
		L.RaiseError("the header only takes bytes while the Hook runs")
		return nil
	}
	if len(builder.bytes)+add > headerLimit {
		L.RaiseError("a header takes at most %d bytes", headerLimit)
		return nil
	}
	return builder
}

func packetLen(L *lua.LState) int {
	xlua.PushNumber(L, int64(len(packetFor(L).data)))
	return 1
}

func packetByte(L *lua.LState) int {
	packet := packetFor(L)
	at := L.CheckNumber(2)
	if !(at >= 1 && int(at) <= len(packet.data)) {
		L.RaiseError("Byte requires an index of 1 to %d", len(packet.data))
		return 0
	}
	xlua.PushNumber(L, int64(packet.data[int(at)-1]))
	return 1
}

func packetMatch(L *lua.LState) int {
	packet := packetFor(L)
	at := L.CheckNumber(2)
	want, ok := L.Get(3).(lua.LString)
	if !ok {
		L.RaiseError("Match requires a string")
		return 0
	}
	if !(at >= 1 && int(at)-1+len(want) <= len(packet.data)) {
		L.Push(lua.LFalse)
		return 1
	}
	L.Push(lua.LBool(string(packet.data[int(at)-1:int(at)-1+len(want)]) == string(want)))
	return 1
}

func packetSlice(L *lua.LState) int {
	packet := packetFor(L)
	from, to := L.CheckNumber(2), L.CheckNumber(3)
	if !(from >= 1 && to >= from && int(to) <= len(packet.data)) {
		L.RaiseError("Slice requires 1 <= from <= to <= %d", len(packet.data))
		return 0
	}
	xlua.PushString(L, string(packet.data[int(from)-1:int(to)]))
	return 1
}

func packetFor(L *lua.LState) *headerPacket {
	packet, err := xlua.ReadUserData[*headerPacket](L.Get(1), "the packet the Hook was given is missing")
	if err != nil {
		L.RaiseError("%s", err.Error())
		return nil
	}
	if !packet.open {
		L.RaiseError("the packet can only be read while the Hook runs")
		return nil
	}
	return packet
}

func luaBuilder(L *lua.LState) (*lua.LUserData, *headerBuilder, error) {
	data, ok := L.GetField(L.G.Registry, headerKey).(*lua.LUserData)
	if !ok {
		return nil, nil, errors.New("header script has no header builder")
	}
	builder, ok := data.Value.(*headerBuilder)
	if !ok {
		return nil, nil, errors.New("header script has no header builder")
	}
	return data, builder, nil
}

func luaPacket(L *lua.LState) (*lua.LUserData, *headerPacket, error) {
	data, ok := L.GetField(L.G.Registry, packetKey).(*lua.LUserData)
	if !ok {
		return nil, nil, errors.New("header script has no packet")
	}
	packet, ok := data.Value.(*headerPacket)
	if !ok {
		return nil, nil, errors.New("header script has no packet")
	}
	return data, packet, nil
}
