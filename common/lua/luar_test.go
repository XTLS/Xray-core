package lua

import (
	"net"
	"testing"

	glua "github.com/yuin/gopher-lua"
	luar "layeh.com/gopher-luar"
)

func TestSlicePusher(t *testing.T) {
	L := glua.NewState()
	defer L.Close()
	push := NewSlicePusher[int](L)
	values := []int{3, 5}
	L.SetGlobal("getValues", L.NewFunction(func(L *glua.LState) int {
		push(L, values)
		return 1
	}))
	if err := L.DoString(`
local values = getValues()
assert(#values == 2 and values[1] == 3 and values[2] == 5)
values[2] = 7
local co = coroutine.create(function()
    local values = getValues()
    assert(#values == 2 and values[1] == 3 and values[2] == 7)
    return true
end)
local ok, result = coroutine.resume(co)
assert(ok and result == true)
`); err != nil {
		t.Fatal(err)
	}
	if values[1] != 7 {
		t.Fatal("slice storage was copied")
	}
	push(L, nil)
	if L.Get(-1) != glua.LNil {
		t.Fatal("nil slice must push Lua nil")
	}
	L.Pop(1)
	push(L, []int{})
	L.SetGlobal("empty", L.Get(-1))
	L.Pop(1)
	if err := L.DoString(`assert(type(empty) == "userdata" and #empty == 0)`); err != nil {
		t.Fatal(err)
	}
}

func TestSlicePusherMetatablePerState(t *testing.T) {
	first := glua.NewState()
	defer first.Close()
	second := glua.NewState()
	defer second.Close()
	NewSlicePusher[int](first)(first, []int{1})
	NewSlicePusher[int](second)(second, []int{1})
	if first.Get(-1).(*glua.LUserData).Metatable == second.Get(-1).(*glua.LUserData).Metatable {
		t.Fatal("independent states share a slice metatable")
	}
}

func BenchmarkSlicePusher(b *testing.B) {
	L := glua.NewState()
	defer L.Close()
	ips := []net.IP{net.ParseIP("127.0.0.1")}
	pushIPs := NewSlicePusher[net.IP](L)
	for _, benchmark := range []struct {
		name string
		push func(*glua.LState, []net.IP)
	}{
		{"bare", func(L *glua.LState, ips []net.IP) { PushUserData(L, ips) }},
		{"luar", func(L *glua.LState, ips []net.IP) { L.Push(luar.New(L, ips)) }},
		{"cached", pushIPs},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchmark.push(L, ips)
				L.Pop(1)
			}
		})
	}
}
