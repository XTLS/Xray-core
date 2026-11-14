package lua

import (
	"net"
	"reflect"
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

func TestReadOnlySlicePusher(t *testing.T) {
	L := glua.NewState()
	defer L.Close()
	values := []int{3, 5}
	NewReadOnlySlicePusher[int](L)(L, values)
	L.SetGlobal("values", L.Get(-1))
	L.Pop(1)
	if err := L.DoString(`
assert(#values == 2 and values[1] == 3 and values[2] == 5)
assert(not pcall(function() values[1] = 7 end))
assert(not pcall(function() return values + 7 end))
local sum = 0
for _, value in values() do sum = sum + value end
assert(sum == 8)
`); err != nil {
		t.Fatal(err)
	}
	got := L.GetGlobal("values").(*glua.LUserData).Value.([]int)
	if &got[0] != &values[0] || values[0] != 3 || values[1] != 5 {
		t.Fatal("read-only binding copied or modified the slice")
	}
}

func TestReadOnlyIPSlicePusher(t *testing.T) {
	L := glua.NewState()
	defer L.Close()
	ips := []net.IP{{192, 0, 2, 1}, net.ParseIP("2001:db8::1")}
	NewReadOnlySlicePusher[net.IP](L)(L, ips)
	L.SetGlobal("ips", L.Get(-1))
	L.Pop(1)
	readOnly := luar.MT(L, ips).RawGetString("__newindex")
	NewReadOnlySlicePusher[net.IP](L)
	if luar.MT(L, ips).RawGetString("__newindex") != readOnly {
		t.Fatal("IP metatables were initialized more than once")
	}
	if err := L.DoString(`
local function readOnly(value)
    assert(not pcall(function() value[1] = value[1] end))
    assert(not pcall(function() return value + value[1] end))
end
assert(#ips == 2 and ips[1]:String() == "192.0.2.1")
readOnly(ips)
for _, ip in ips() do
    readOnly(ip)
    readOnly(ip:To16())
    if ip:To4() then
        readOnly(ip:To4())
        readOnly(ip:DefaultMask())
    end
    assert(ip:Equal(ip:To16()) and type(ip:String()) == "string")
    assert(ip.AppendText == nil and ip.appendText == nil)
    local text, err = ip:MarshalText()
    assert(not err)
    text[1] = 88 -- Independently owned byte buffers remain writable.
    assert(not pcall(function() return ips + text end))
end
`); err != nil {
		t.Fatal(err)
	}
	got := L.GetGlobal("ips").(*glua.LUserData).Value.([]net.IP)
	if &got[0] != &ips[0] || &got[0][0] != &ips[0][0] || &got[1][0] != &ips[1][0] {
		t.Fatal("read-only binding copied the IP data")
	}
	for i, want := range []string{"192.0.2.1", "2001:db8::1"} {
		if got[i].String() != want {
			t.Fatalf("IP %d changed to %s; want %s", i, got[i], want)
		}
	}
}

func TestReadOnlyIPSlicePusherLazy(t *testing.T) {
	for _, tc := range []struct{ name, access string }{
		{"index", `local ip = ips[1]`},
		{"iterate", `local _, ip = ips()()`},
		{"coroutine", `local co = coroutine.create(function() return ips[1] end); local ok, ip = coroutine.resume(co); assert(ok)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			L := glua.NewState()
			defer L.Close()
			methods := 0
			luar.GetConfig(L).MethodNames = func(_ reflect.Type, method reflect.Method) []string {
				methods++
				return []string{method.Name}
			}
			NewReadOnlySlicePusher[net.IP](L)(L, []net.IP{{192, 0, 2, 1}})
			L.SetGlobal("ips", L.Get(-1))
			L.Pop(1)
			if err := L.DoString(`assert(#ips == 1); assert(not pcall(function() ips[1] = nil end))`); err != nil {
				t.Fatal(err)
			}
			if methods != 0 {
				t.Fatal("IP methods initialized without reading an element")
			}
			source := tc.access + `
assert(ip:String() == "192.0.2.1" and ip.AppendText == nil)
assert(not pcall(function() ip[1] = 0 end))
assert(not pcall(function() ip:To4()[1] = 0 end))
assert(not pcall(function() ip:To16()[1] = 0 end))
assert(not pcall(function() ip:DefaultMask()[1] = 0 end))
`
			if err := L.DoString(source); err != nil {
				t.Fatal(err)
			}
			initialized := methods
			if initialized == 0 {
				t.Fatal("IP access did not initialize its methods")
			}
			if err := L.DoString(source); err != nil {
				t.Fatal(err)
			}
			if methods != initialized {
				t.Fatal("IP methods initialized more than once")
			}
		})
	}
}

func TestReadOnlyNestedSlicePusher(t *testing.T) {
	L := glua.NewState()
	defer L.Close()
	values := [][][]byte{{{3, 5}}}
	NewReadOnlySlicePusher[[][]byte](L)(L, values)
	L.SetGlobal("values", L.Get(-1))
	L.Pop(1)
	ips := [][]net.IP{{{192, 0, 2, 1}}}
	NewReadOnlySlicePusher[[]net.IP](L)(L, ips)
	L.SetGlobal("ips", L.Get(-1))
	L.Pop(1)
	if err := L.DoString(`
local function readOnly(value)
    assert(not pcall(function() value[1] = value[1] end))
    assert(not pcall(function() return value + value[1] end))
end
assert(values[1][1][1] == 3 and values[1][1][2] == 5)
readOnly(values)
for _, group in values() do
    readOnly(group)
    for _, bytes in group() do readOnly(bytes) end
end
readOnly(ips)
readOnly(ips[1])
local ip = ips[1][1]
assert(ip:String() == "192.0.2.1")
readOnly(ip)
readOnly(ip:To4())
readOnly(ip:To16())
readOnly(ip:DefaultMask())
assert(ip.AppendText == nil and ip.appendText == nil)
`); err != nil {
		t.Fatal(err)
	}
	readOnly := luar.MT(L, ips[0]).RawGetString("__newindex")
	NewReadOnlySlicePusher[net.IP](L)
	if luar.MT(L, ips[0]).RawGetString("__newindex") != readOnly {
		t.Fatal("nested slice metatable was initialized again")
	}
	got := L.GetGlobal("values").(*glua.LUserData).Value.([][][]byte)
	if &got[0][0][0] != &values[0][0][0] || values[0][0][0] != 3 || values[0][0][1] != 5 {
		t.Fatal("read-only binding copied or modified the nested slice")
	}
}

type recursiveReadOnlySlice []recursiveReadOnlySlice

func TestReadOnlyRecursiveSlicePusher(t *testing.T) {
	L := glua.NewState()
	defer L.Close()
	values := make(recursiveReadOnlySlice, 1)
	values[0] = values
	NewReadOnlySlicePusher[recursiveReadOnlySlice](L)(L, values)
	L.SetGlobal("values", L.Get(-1))
	L.Pop(1)
	if err := L.DoString(`
local nested = values[1][1][1]
assert(#nested == 1)
assert(not pcall(function() nested[1] = nested end))
assert(not pcall(function() return nested + nested end))
`); err != nil {
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
