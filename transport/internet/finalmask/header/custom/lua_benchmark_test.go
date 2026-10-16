package custom

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

func BenchmarkLuaHeaderWrite(b *testing.B) {
	b.Run("static", func(b *testing.B) {
		items := []*UDPItem{{Packet: []byte{1, 2}}, {Rand: 2, RandMax: 255}}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			header, err := evaluateUDPItems(items)
			if err != nil {
				b.Fatal(err)
			}
			if len(header) != 4 {
				b.Fatalf("got %d bytes, want 4", len(header))
			}
		}
	})

	b.Run("script", func(b *testing.B) { benchmarkHeaderWrite(b) })
}

func benchmarkHeaderWrite(b *testing.B) {
	engine := benchmarkEngine(b, packetScript)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		header, err := engine.header(roleClient, "192.0.2.1:443", nil)
		if err != nil {
			b.Fatal(err)
		}
		if len(header) != 4 {
			b.Fatalf("got %d bytes, want 4", len(header))
		}
	}
}

func BenchmarkLuaHeaderRead(b *testing.B) {
	engine := benchmarkEngine(b, packetScript)
	packet := []byte{1, 2, 0, 0, 'p', 'a', 'y'}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		strip, err := engine.strip(roleServer, "192.0.2.1:443", packet)
		if err != nil {
			b.Fatal(err)
		}
		if strip != 4 {
			b.Fatalf("got %d, want 4", strip)
		}
	}
}
