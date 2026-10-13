package noise

import (
	"crypto/rand"
	"time"

	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	xlua "github.com/xtls/xray-core/common/lua"
	lua "github.com/yuin/gopher-lua"
)

const (
	valueLimit  = 65535
	packetLimit = 64
)

const planKey = "xray.finalmask.noise.plan"

type noisePlan struct {
	packets []scriptPacket
	bytes   int
	open    bool
}

func RegisterLua(L *lua.LState) {
	L.PreloadModule("xray.finalmask.noise", func(L *lua.LState) int {
		module := L.CreateTable(0, 2)

		module.RawSetString("Random", L.NewFunction(func(L *lua.LState) int {
			size := L.CheckNumber(1)
			if !(size >= 0 && size <= valueLimit) {
				L.RaiseError("noise.Random requires a size of 0 to %d", valueLimit)
				return 0
			}
			buf := make([]byte, int(size))
			if _, err := rand.Read(buf); err != nil {
				L.RaiseError("noise.Random failed: %v", err)
				return 0
			}
			xlua.PushString(L, string(buf))
			return 1
		}))

		module.RawSetString("RandomBetween", L.NewFunction(func(L *lua.LState) int {
			from, to := L.CheckNumber(1), L.CheckNumber(2)
			if !(from >= 0 && from <= to && to <= valueLimit) {
				L.RaiseError("noise.RandomBetween requires 0 <= from <= to <= %d", valueLimit)
				return 0
			}
			xlua.PushNumber(L, crypto.RandBetween(int64(from), int64(to)+1))
			return 1
		}))

		L.Push(module)
		return 1
	})
}

func registerPlan(L *lua.LState) {
	meta := L.CreateTable(0, 3)
	meta.RawSetString("__index", meta)
	meta.RawSetString("Add", L.NewFunction(planAdd))
	meta.RawSetString("AddRandom", L.NewFunction(planAddRandom))

	data := L.NewUserData()
	data.Value = &noisePlan{}
	data.Metatable = meta
	L.SetField(L.G.Registry, planKey, data)
}

func planAdd(L *lua.LState) int {
	packet, ok := L.Get(2).(lua.LString)
	if !ok {
		L.RaiseError("Add requires a packet string")
		return 0
	}
	plan := planFor(L, len(packet))
	plan.packets = append(plan.packets, scriptPacket{packet: []byte(packet), delay: planDelay(L, 3)})
	plan.bytes += len(packet)
	return 0
}

func planAddRandom(L *lua.LState) int {
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
	plan.packets = append(plan.packets, scriptPacket{packet: packet, delay: planDelay(L, 3)})
	plan.bytes += int(size)
	return 0
}

func planFor(L *lua.LState, size int) *noisePlan {
	plan, err := xlua.ReadUserData[*noisePlan](L.Get(1), "the plan HandleNoise was given is missing")
	if err != nil {
		L.RaiseError("%s", err.Error())
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

func planDelay(L *lua.LState, index int) time.Duration {
	switch value := L.Get(index).(type) {
	case *lua.LNilType:
		return 0
	case lua.LNumber:
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

func luaPlan(L *lua.LState) (*lua.LUserData, *noisePlan, error) {
	data, ok := L.GetField(L.G.Registry, planKey).(*lua.LUserData)
	if !ok {
		return nil, nil, errors.New("noise script has no plan")
	}
	plan, ok := data.Value.(*noisePlan)
	if !ok {
		return nil, nil, errors.New("noise script has no plan")
	}
	return data, plan, nil
}
