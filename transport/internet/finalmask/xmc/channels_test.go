package xmc

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestChannelIDsDefaults(t *testing.T) {
	dataChannel, paddingChannel, err := (&Config{}).ChannelIDs()
	if err != nil {
		t.Fatalf("default channels: %v", err)
	}
	if dataChannel != DefaultDataChannel || paddingChannel != DefaultPaddingChannel {
		t.Fatalf("defaults = %q, %q", dataChannel, paddingChannel)
	}
}

func TestChannelIDsConfigured(t *testing.T) {
	config := &Config{DataChannel: "myxmc:stream", PaddingChannel: "myxmc:noise"}
	dataChannel, paddingChannel, err := config.ChannelIDs()
	if err != nil {
		t.Fatalf("configured channels: %v", err)
	}
	if dataChannel != "myxmc:stream" || paddingChannel != "myxmc:noise" {
		t.Fatalf("channels = %q, %q", dataChannel, paddingChannel)
	}
}

func TestChannelIDsRejectEqualChannels(t *testing.T) {
	config := &Config{DataChannel: "myxmc:same", PaddingChannel: "myxmc:same"}
	if _, _, err := config.ChannelIDs(); err == nil {
		t.Fatal("expected an error for one channel used twice")
	}
}

func TestValidateChannelID(t *testing.T) {
	tests := []struct {
		id string
		ok bool
	}{
		{"xmc:data", true},
		{"a:b", true},
		{"my-xmc:v1/main.data", true},
		{strings.Repeat("a", 126) + ":b", true}, // exactly 128 bytes
		{"", false},
		{"xmcdata", false},
		{"xmc:data:extra", false},
		{":data", false},
		{"xmc:", false},
		{"Xmc:data", false},
		{"xmc:Data", false},
		{"..:data", false},
		{"xmc:data space", false},
		{"xmc:data!", false},
		{"minecraft:data", false},
		{"minecraft:brand", false},
		{strings.Repeat("a", 127) + ":b", false}, // 129 bytes
	}
	for _, test := range tests {
		err := ValidateChannelID(test.id)
		if test.ok && err != nil {
			t.Fatalf("%q: unexpected error %v", test.id, err)
		}
		if !test.ok && err == nil {
			t.Fatalf("%q: expected an error", test.id)
		}
	}
}

// TestPaddingFramingDependsOnChannelLength pins that the exact frame lengths of
// a captured preset follow the configured channel name instead of the default.
func TestPaddingFramingDependsOnChannelLength(t *testing.T) {
	const channel = "my-long-namespace:padding-channel"
	framing := newPaddingFraming(channel)
	if got, want := framing.overhead(), defaultPaddingFraming.overhead()+len(channel)-len(DefaultPaddingChannel); got != want {
		t.Fatalf("overhead = %d, want %d", got, want)
	}
	for _, length := range []int{1024, 48 * 1024, 1024 * 1024} {
		plan, err := framing.plan(length)
		if err != nil {
			t.Fatalf("plan %d: %v", length, err)
		}
		total := 0
		for _, frameLength := range plan {
			if _, ok := framing.frameDataLength(frameLength); !ok {
				t.Fatalf("plan %d contains unreachable frame %d", length, frameLength)
			}
			total += frameLength
		}
		if total != length {
			t.Fatalf("plan %d totals %d", length, total)
		}
	}
}

// TestPaddingChannelIsConfigurable checks that the startup-padding reader drains
// exactly the configured channel and leaves every other payload alone.
func TestPaddingChannelIsConfigurable(t *testing.T) {
	const paddingChannel = "myxmc:noise"
	packetID := paddingFramePacketID(configurationPacketIDs121, false)

	build := func() []byte {
		var wire bytes.Buffer
		channel := String(paddingChannel)
		padding := RestBytes(make([]byte, 64))
		if err := writePacket(&wire, packetID, &channel, &padding); err != nil {
			t.Fatal(err)
		}
		following := String(DefaultDataChannel)
		payload := RestBytes("tunnel bytes")
		if err := writePacket(&wire, packetID, &following, &payload); err != nil {
			t.Fatal(err)
		}
		return wire.Bytes()
	}

	channelOf := func(frame []byte) string {
		t.Helper()
		packet, err := readPacket(bytes.NewReader(frame))
		if err != nil {
			t.Fatal(err)
		}
		var channel String
		if err := channel.readFrom(bytes.NewReader(packet.data)); err != nil {
			t.Fatal(err)
		}
		return string(channel)
	}

	frame, err := readPastPadding(bytes.NewReader(build()), packetID, paddingChannel)
	if err != nil {
		t.Fatalf("readPastPadding: %v", err)
	}
	if got := channelOf(frame); got != DefaultDataChannel {
		t.Fatalf("drained past the configured padding channel, got %q", got)
	}

	// A different configured name must not silently drop the frame.
	frame, err = readPastPadding(bytes.NewReader(build()), packetID, "other:pad")
	if err != nil {
		t.Fatalf("readPastPadding with another channel: %v", err)
	}
	if got := channelOf(frame); got != paddingChannel {
		t.Fatalf("expected the unrecognized frame back, got %q", got)
	}
}

// TestTickStreamUsesConfiguredChannels checks that a configured pair reaches the
// wire: data payloads on the data channel, idle ticks on the padding channel.
func TestTickStreamUsesConfiguredChannels(t *testing.T) {
	const (
		dataChannel    = "myxmc:stream"
		paddingChannel = "myxmc:noise"
	)
	writer := &tickTestWriter{}
	stream := newTickStream(nil, writer, true, configurationPacketIDs121, dataChannel, paddingChannel)
	defer stream.Stop()

	if _, err := stream.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(120 * time.Millisecond)
	stream.Stop()
	_ = stream.Flush()

	seenData, seenPadding := false, false
	for _, batch := range writer.snapshot() {
		for _, packet := range readTickBatch(t, batch) {
			channel, payload := tickPacketChannelAndPayload(t, packet)
			switch channel {
			case dataChannel:
				seenData = true
				if !bytes.Equal(payload, []byte("hello")) {
					t.Fatalf("data payload = %q", payload)
				}
			case paddingChannel:
				seenPadding = true
			default:
				t.Fatalf("unexpected channel %q", channel)
			}
		}
	}
	if !seenData || !seenPadding {
		t.Fatalf("configured channels not used: data=%v padding=%v", seenData, seenPadding)
	}
}
