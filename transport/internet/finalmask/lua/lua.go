package lua

import (
	"crypto/rand"
	"io"
	"net"
	"time"

	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	xlua "github.com/xtls/xray-core/common/lua"
	glua "github.com/yuin/gopher-lua"
)

const (
	valueLimit  = 65535
	packetLimit = 64
	headerLimit = 1024
)

const (
	planKey   = "xray.finalmask.plan"
	streamKey = "xray.finalmask.stream"
	headerKey = "xray.finalmask.header"
	packetKey = "xray.finalmask.packet"
)

type noisePlan struct {
	packets []scriptPacket
	bytes   int
	open    bool
}

type headerStream struct {
	conn    net.Conn
	written int
	read    int
	open    bool
}

type headerBuilder struct {
	bytes []byte
	open  bool
}

type headerPacket struct {
	data []byte
	open bool
}

func RegisterLua(L *glua.LState) {
	L.PreloadModule("xray.finalmask", func(L *glua.LState) int {
		module := L.CreateTable(0, 2)

		module.RawSetString("Random", L.NewFunction(func(L *glua.LState) int {
			size := L.CheckNumber(1)
			if !(size >= 0 && size <= valueLimit) {
				L.RaiseError("Random requires a size of 0 to %d", valueLimit)
				return 0
			}
			buf := make([]byte, int(size))
			if _, err := rand.Read(buf); err != nil {
				L.RaiseError("Random failed: %v", err)
				return 0
			}
			xlua.PushString(L, string(buf))
			return 1
		}))

		module.RawSetString("RandomBetween", L.NewFunction(func(L *glua.LState) int {
			from, to := L.CheckNumber(1), L.CheckNumber(2)
			if !(from >= 0 && from <= to && to <= valueLimit) {
				L.RaiseError("RandomBetween requires 0 <= from <= to <= %d", valueLimit)
				return 0
			}
			xlua.PushNumber(L, crypto.RandBetween(int64(from), int64(to)+1))
			return 1
		}))

		L.Push(module)
		return 1
	})
}

func registerObjects(L *glua.LState) {
	planMeta := L.CreateTable(0, 3)
	planMeta.RawSetString("__index", planMeta)
	planMeta.RawSetString("Add", L.NewFunction(planAdd))
	planMeta.RawSetString("AddRandom", L.NewFunction(planAddRandom))
	setObject(L, planKey, planMeta, &noisePlan{})

	streamMeta := L.CreateTable(0, 4)
	streamMeta.RawSetString("__index", streamMeta)
	streamMeta.RawSetString("Write", L.NewFunction(streamWrite))
	streamMeta.RawSetString("Read", L.NewFunction(streamRead))
	streamMeta.RawSetString("Sleep", L.NewFunction(streamSleep))
	setObject(L, streamKey, streamMeta, &headerStream{})

	headerMeta := L.CreateTable(0, 3)
	headerMeta.RawSetString("__index", headerMeta)
	headerMeta.RawSetString("Add", L.NewFunction(builderAdd))
	headerMeta.RawSetString("AddRandom", L.NewFunction(builderAddRandom))
	setObject(L, headerKey, headerMeta, &headerBuilder{})

	packetMeta := L.CreateTable(0, 5)
	packetMeta.RawSetString("__index", packetMeta)
	packetMeta.RawSetString("Len", L.NewFunction(packetLen))
	packetMeta.RawSetString("Byte", L.NewFunction(packetByte))
	packetMeta.RawSetString("Match", L.NewFunction(packetMatch))
	packetMeta.RawSetString("Slice", L.NewFunction(packetSlice))
	setObject(L, packetKey, packetMeta, &headerPacket{})
}

func setObject(L *glua.LState, key string, meta *glua.LTable, value any) {
	data := L.NewUserData()
	data.Value = value
	data.Metatable = meta
	L.SetField(L.G.Registry, key, data)
}

func object[T any](L *glua.LState, key string) (*glua.LUserData, T, error) {
	var zero T
	data, ok := L.GetField(L.G.Registry, key).(*glua.LUserData)
	if !ok {
		return nil, zero, errors.New("the script has no ", key)
	}
	value, ok := data.Value.(T)
	if !ok {
		return nil, zero, errors.New("the script has no ", key)
	}
	return data, value, nil
}

func planAdd(L *glua.LState) int {
	packet, ok := L.Get(2).(glua.LString)
	if !ok {
		L.RaiseError("Add requires a packet string")
		return 0
	}
	plan := planFor(L, len(packet))
	plan.packets = append(plan.packets, scriptPacket{packet: []byte(packet), delay: readDelay(L, 3)})
	plan.bytes += len(packet)
	return 0
}

func planAddRandom(L *glua.LState) int {
	size := L.CheckNumber(2)
	if !(size >= 0 && size <= valueLimit) {
		L.RaiseError("AddRandom requires a size of 0 to %d", valueLimit)
		return 0
	}
	plan := planFor(L, int(size))
	packet := make([]byte, int(size))
	if _, err := rand.Read(packet); err != nil {
		L.RaiseError("AddRandom failed: %v", err)
		return 0
	}
	plan.packets = append(plan.packets, scriptPacket{packet: packet, delay: readDelay(L, 3)})
	plan.bytes += int(size)
	return 0
}

func planFor(L *glua.LState, size int) *noisePlan {
	_, plan, err := object[*noisePlan](L, planKey)
	if err != nil || L.Get(1) != L.GetField(L.G.Registry, planKey) {
		L.RaiseError("the plan HandleNoise was given is required")
		return nil
	}
	if !plan.open {
		L.RaiseError("the plan only takes packets while HandleNoise runs")
		return nil
	}
	if len(plan.packets) >= packetLimit {
		L.RaiseError("the plan takes at most %d packets per call", packetLimit)
		return nil
	}
	if plan.bytes+size > valueLimit {
		L.RaiseError("the plan takes at most %d bytes of noise per call", valueLimit)
		return nil
	}
	return plan
}

func streamWrite(L *glua.LState) int {
	packet, ok := L.Get(2).(glua.LString)
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

func streamRead(L *glua.LState) int {
	size := L.CheckNumber(2)
	if !(size >= 1 && size <= valueLimit) {
		L.RaiseError("Read requires a size of 1 to %d", valueLimit)
		return 0
	}
	stream := streamFor(L, 0)
	if stream.read+int(size) > valueLimit {
		L.RaiseError("a handshake reads at most %d bytes", valueLimit)
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

func streamSleep(L *glua.LState) int {
	delay := L.CheckNumber(2)
	if !(delay >= 0 && delay <= valueLimit) {
		L.RaiseError("Sleep requires a delay of 0 to %d milliseconds", valueLimit)
		return 0
	}
	streamFor(L, 0)
	timer := time.NewTimer(time.Duration(delay) * time.Millisecond)
	defer timer.Stop()
	ctx := L.Context()
	if ctx == nil {
		<-timer.C
		return 0
	}
	select {
	case <-timer.C:
	case <-ctx.Done():
		L.RaiseError("Sleep was cut short: %v", ctx.Err())
	}
	return 0
}

func streamFor(L *glua.LState, write int) *headerStream {
	_, stream, err := object[*headerStream](L, streamKey)
	if err != nil || L.Get(1) != L.GetField(L.G.Registry, streamKey) {
		L.RaiseError("the stream HandleHeader was given is required")
		return nil
	}
	if !stream.open {
		L.RaiseError("the stream only works while HandleHeader runs")
		return nil
	}
	if stream.written+write > valueLimit {
		L.RaiseError("a handshake writes at most %d bytes", valueLimit)
		return nil
	}
	return stream
}

func builderAdd(L *glua.LState) int {
	bytes, ok := L.Get(2).(glua.LString)
	if !ok {
		L.RaiseError("Add requires a string")
		return 0
	}
	builder := builderFor(L, len(bytes))
	builder.bytes = append(builder.bytes, bytes...)
	return 0
}

func builderAddRandom(L *glua.LState) int {
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

func builderFor(L *glua.LState, add int) *headerBuilder {
	_, builder, err := object[*headerBuilder](L, headerKey)
	if err != nil || L.Get(1) != L.GetField(L.G.Registry, headerKey) {
		L.RaiseError("the header HandleHeaderWrite was given is required")
		return nil
	}
	if !builder.open {
		L.RaiseError("the header only takes bytes while HandleHeaderWrite runs")
		return nil
	}
	if len(builder.bytes)+add > headerLimit {
		L.RaiseError("a header takes at most %d bytes", headerLimit)
		return nil
	}
	return builder
}

func packetLen(L *glua.LState) int {
	xlua.PushNumber(L, int64(len(packetFor(L).data)))
	return 1
}

func packetByte(L *glua.LState) int {
	packet := packetFor(L)
	at := L.CheckNumber(2)
	if !(at >= 1 && int(at) <= len(packet.data)) {
		L.RaiseError("Byte requires an index of 1 to %d", len(packet.data))
		return 0
	}
	xlua.PushNumber(L, int64(packet.data[int(at)-1]))
	return 1
}

func packetMatch(L *glua.LState) int {
	packet := packetFor(L)
	at := L.CheckNumber(2)
	want, ok := L.Get(3).(glua.LString)
	if !ok {
		L.RaiseError("Match requires a string")
		return 0
	}
	if !(at >= 1 && int(at)-1+len(want) <= len(packet.data)) {
		L.Push(glua.LFalse)
		return 1
	}
	L.Push(glua.LBool(string(packet.data[int(at)-1:int(at)-1+len(want)]) == string(want)))
	return 1
}

func packetSlice(L *glua.LState) int {
	packet := packetFor(L)
	from, to := L.CheckNumber(2), L.CheckNumber(3)
	if !(from >= 1 && to >= from && int(to) <= len(packet.data)) {
		L.RaiseError("Slice requires 1 <= from <= to <= %d", len(packet.data))
		return 0
	}
	xlua.PushString(L, string(packet.data[int(from)-1:int(to)]))
	return 1
}

func packetFor(L *glua.LState) *headerPacket {
	_, packet, err := object[*headerPacket](L, packetKey)
	if err != nil || L.Get(1) != L.GetField(L.G.Registry, packetKey) {
		L.RaiseError("the packet HandleHeaderRead was given is required")
		return nil
	}
	if !packet.open {
		L.RaiseError("the packet can only be read while HandleHeaderRead runs")
		return nil
	}
	return packet
}

func readDelay(L *glua.LState, index int) time.Duration {
	switch value := L.Get(index).(type) {
	case *glua.LNilType:
		return 0
	case glua.LNumber:
		if !(value >= 0 && value <= valueLimit) {
			L.RaiseError("the delay must be 0 to %d milliseconds", valueLimit)
			return 0
		}
		return time.Duration(value) * time.Millisecond
	default:
		L.RaiseError("the delay must be a number of milliseconds")
		return 0
	}
}
