package noise

import "testing"

func benchmarkEngine(b *testing.B, script string) *scriptEngine {
	b.Helper()
	engine, err := newScriptEngine(writeScript(b, script))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(engine.pool.Close)
	return engine
}

func benchmarkPackets(b *testing.B, engine *scriptEngine, want int) {
	b.Helper()
	b.ReportAllocs()
	var buf []scriptPacket
	for i := 0; i < b.N; i++ {
		packets, err := engine.packets("192.0.2.1:443", buf[:0])
		if err != nil {
			b.Fatal(err)
		}
		if len(packets) != want {
			b.Fatalf("got %d packets, want %d", len(packets), want)
		}
		buf = packets
	}
}

func BenchmarkLuaNoiseHook(b *testing.B) {
	benchmarkPackets(b, benchmarkEngine(b, `function HandleNoise(plan, address) end`), 0)
}

func BenchmarkLuaNoisePackets(b *testing.B) {
	b.Run("add", func(b *testing.B) {
		benchmarkPackets(b, benchmarkEngine(b, `
local noise = require("xray.finalmask.noise")

function HandleNoise(plan, address)
    plan:Add(noise.Random(64))
    plan:Add(noise.Random(64), 0)
end
`), 2)
	})

	b.Run("addrandom", func(b *testing.B) {
		benchmarkPackets(b, benchmarkEngine(b, `
function HandleNoise(plan, address)
    plan:AddRandom(64)
    plan:AddRandom(64, 0)
end
`), 2)
	})

	b.Run("static", func(b *testing.B) {
		conn := &noiseConn{config: &Config{Items: []*Item{
			{RandMin: 64, RandMax: 64, RandRangeMax: 255},
			{RandMin: 64, RandMax: 64, RandRangeMax: 255},
		}}}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, item := range conn.config.Items {
				if len(conn.buildPacket(item)) != 64 {
					b.Fatal("unexpected packet size")
				}
			}
		}
	})
}
