package conf

import (
	"testing"

	"github.com/xtls/xray-core/transport/internet/finalmask/noise"
)

func buildNoiseTag(tag string) (*noise.Config, error) {
	msg, err := (&NoiseMask{Noise: []NoiseItem{{Tag: tag}}}).Build()
	if err != nil {
		return nil, err
	}
	return msg.(*noise.Config), nil
}

func TestNoiseTag(t *testing.T) {
	cfg, err := buildNoiseTag("<b 0d0a0d0a><t><r 24><rc 20-40><rd 8><c><n>")
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

func TestNoiseTagStripsHexPrefix(t *testing.T) {
	cfg, err := buildNoiseTag("<b 0x16030100>")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Items[0].Segments[0].Bytes; string(got) != string([]byte{0x16, 0x03, 0x01, 0x00}) {
		t.Errorf("got %x", got)
	}
}

func TestNoiseTagWhitespace(t *testing.T) {
	if _, err := buildNoiseTag("  <b 00>  <t>  "); err != nil {
		t.Errorf("surrounding whitespace should be allowed: %v", err)
	}
	cfg, err := buildNoiseTag("<b 0d 0a 0d 0a>")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Items[0].Segments[0].Bytes; string(got) != "\r\n\r\n" {
		t.Errorf("got %x", got)
	}
}

func TestNoiseTagRejects(t *testing.T) {
	for _, tag := range []string{
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
		if _, err := buildNoiseTag(tag); err == nil {
			t.Errorf("expected an error for %q", tag)
		}
	}
}

func TestNoiseTagConflicts(t *testing.T) {
	if _, err := (&NoiseMask{Noise: []NoiseItem{{Tag: "<t>", Rand: Int32Range{From: 10, To: 20}}}}).Build(); err == nil {
		t.Error("tag with rand should be rejected")
	}
}
