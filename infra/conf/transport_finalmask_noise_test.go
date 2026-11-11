package conf

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/transport/internet/finalmask/noise"
)

func expPacket(exp string) json.RawMessage {
	b, _ := json.Marshal(exp)
	return b
}

func buildNoiseExp(exp string) (*noise.Config, error) {
	msg, err := (&NoiseMask{Noise: []NoiseItem{{Type: "exp", Packet: expPacket(exp)}}}).Build()
	if err != nil {
		return nil, err
	}
	return msg.(*noise.Config), nil
}

func TestNoiseExp(t *testing.T) {
	cfg, err := buildNoiseExp("<b 0d0a0d0a><t><r 24><rc 20-40><rd 8><c><n>")
	if err != nil {
		t.Fatal(err)
	}
	segments := cfg.Items[0].Segments
	if len(segments) != 7 {
		t.Fatalf("got %d segments, want 7", len(segments))
	}
	want := []struct {
		kind     noise.Segment_Kind
		bytes    []byte
		min, max int64
	}{
		{noise.Segment_BYTES, []byte{0x0d, 0x0a, 0x0d, 0x0a}, 0, 0},
		{noise.Segment_TIMESTAMP, nil, 0, 0},
		{noise.Segment_RANDOM, nil, 24, 24},
		{noise.Segment_RANDOM_ASCII, nil, 20, 40},
		{noise.Segment_RANDOM_DIGIT, nil, 8, 8},
		{noise.Segment_COUNTER, nil, 0, 0},
		{noise.Segment_NONCE, nil, 0, 0},
	}
	for i, w := range want {
		s := segments[i]
		if s.Kind != w.kind || s.MinSize != w.min || s.MaxSize != w.max || string(s.Bytes) != string(w.bytes) {
			t.Errorf("segment %d = %+v, want %+v", i, s, w)
		}
	}
}

func TestNoiseExpStripsHexPrefix(t *testing.T) {
	cfg, err := buildNoiseExp("<b 0x16030100>")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Items[0].Segments[0].Bytes; string(got) != string([]byte{0x16, 0x03, 0x01, 0x00}) {
		t.Errorf("got %x", got)
	}
}

func TestNoiseExpWhitespace(t *testing.T) {
	if _, err := buildNoiseExp("  <b 00>  <t>  "); err != nil {
		t.Errorf("surrounding whitespace should be allowed: %v", err)
	}
	cfg, err := buildNoiseExp("<b 0d 0a 0d 0a>")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Items[0].Segments[0].Bytes; string(got) != "\r\n\r\n" {
		t.Errorf("got %x", got)
	}
}

func TestNoiseExpRejects(t *testing.T) {
	for _, exp := range []string{
		"<x 1>",
		"<b>",
		"<b zz>",
		"<b 0d0>",
		"<r>",
		"<r -1>",
		"<r 40-20>",
		"<r 70000>",
		"<t 5>",
		"<n 5>",
		"garbage<t>",
		"<t> tail",
		"<t><b>",
	} {
		if _, err := buildNoiseExp(exp); err == nil {
			t.Errorf("expected an error for %q", exp)
		}
	}
}

func TestNoiseExpConflicts(t *testing.T) {
	if _, err := (&NoiseMask{Noise: []NoiseItem{{Type: "exp", Packet: expPacket("<t>"), Rand: Int32Range{From: 10, To: 20}}}}).Build(); err == nil {
		t.Error("exp with rand should be rejected")
	}
	for _, packet := range []string{``, `[1, 2]`, `5`} {
		if _, err := (&NoiseMask{Noise: []NoiseItem{{Type: "exp", Packet: json.RawMessage(packet)}}}).Build(); err == nil {
			t.Errorf("expected an error for packet %q", packet)
		}
	}
}

func TestNoiseExpFromJSON(t *testing.T) {
	var mask NoiseMask
	if err := json.Unmarshal([]byte(`{"noise": [
		{"type": "exp", "packet": "<b 504f5354><rd 10-20>", "delay": "1-3"},
		{"type": "EXP", "packet": "<t>"},
		{"type": "str", "packet": "<t>"},
		{"rand": "10-20"}
	]}`), &mask); err != nil {
		t.Fatal(err)
	}
	msg, err := mask.Build()
	if err != nil {
		t.Fatal(err)
	}
	items := msg.(*noise.Config).Items
	if len(items[0].Segments) != 2 || items[0].DelayMin != 1 || items[0].DelayMax != 3 {
		t.Errorf("item 0 = %+v", items[0])
	}
	if len(items[1].Segments) != 1 || items[1].Segments[0].Kind != noise.Segment_TIMESTAMP {
		t.Errorf("item 1 = %+v", items[1])
	}
	if len(items[2].Segments) != 0 || string(items[2].Packet) != "<t>" {
		t.Errorf("item 2 = %+v", items[2])
	}
	if len(items[3].Segments) != 0 || items[3].RandMin != 10 || items[3].RandMax != 20 {
		t.Errorf("item 3 = %+v", items[3])
	}
}
