package xmc

import (
	"bytes"
	"testing"
	"time"
)

func TestPaddingFrameDataLengthRoundTrip(t *testing.T) {
	for dataLength := 0; dataLength <= maxPaddingFrameDataLength; dataLength++ {
		frameLength := paddingFrameLength(dataLength)
		got, ok := paddingFrameDataLength(frameLength)
		if !ok || got != dataLength {
			t.Fatalf("data length %d -> frame %d -> data %d (ok=%v)", dataLength, frameLength, got, ok)
		}
	}
}

func TestPaddingFramePlanTotals(t *testing.T) {
	lengths := []int{paddingFrameOverhead, paddingFrameOverhead + 1, 128, 129, 130, 131, 140, 1024, 48 * 1024, maxPaddingFrameLength - 1, maxPaddingFrameLength, maxPaddingFrameLength + 1, 3 * maxPaddingFrameLength, 1024 * 1024}
	for _, length := range lengths {
		plan, err := paddingFramePlan(length)
		if err != nil {
			t.Fatalf("plan %d: %v", length, err)
		}
		total := 0
		for _, frameLength := range plan {
			if _, ok := paddingFrameDataLength(frameLength); !ok {
				t.Fatalf("plan %d contains unreachable frame %d", length, frameLength)
			}
			if frameLength > maxPaddingFrameLength {
				t.Fatalf("plan %d contains oversized frame %d", length, frameLength)
			}
			total += frameLength
		}
		if total != length {
			t.Fatalf("plan %d totals %d", length, total)
		}
	}
}

func TestPaddingFramePlanRoundsUpShortTurn(t *testing.T) {
	plan, err := paddingFramePlan(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 1 || plan[0] != paddingFrameOverhead {
		t.Fatalf("short turn plan = %v", plan)
	}
}

func TestWritePaddingTurnFramesIsMinecraftTraffic(t *testing.T) {
	turns := []paddingTurn{
		{direction: paddingClientToServer, minLength: 44, maxLength: 44},
		{direction: paddingClientToServer, minLength: 2, maxLength: 2},
		{direction: paddingClientToServer, minLength: maxPaddingFrameLength, maxLength: maxPaddingFrameLength},
		{direction: paddingClientToServer, minLength: 3*maxPaddingFrameLength + 7, maxLength: 3*maxPaddingFrameLength + 7},
	}
	for i, turn := range turns {
		var buffer bytes.Buffer
		written, err := writePaddingTurnFrames(&buffer, turn, 0, func(time.Duration) {}, configurationServerboundCustomPayload)
		if err != nil {
			t.Fatalf("turn %d: %v", i, err)
		}
		if written != buffer.Len() {
			t.Fatalf("turn %d wrote %d bytes, buffer has %d", i, written, buffer.Len())
		}
		target := turn.minLength
		if written < target {
			t.Fatalf("turn %d wrote %d bytes, want at least %d", i, written, target)
		}

		reader := bytes.NewReader(buffer.Bytes())
		frames := 0
		for reader.Len() > 0 {
			packet, err := readPacket(reader)
			if err != nil {
				t.Fatalf("turn %d frame %d is not a valid packet: %v", i, frames, err)
			}
			if packet.packetID != configurationServerboundCustomPayload {
				t.Fatalf("turn %d frame %d has packet id %d", i, frames, packet.packetID)
			}
			_, ok, err := parseCustomPayload(packet)
			if err != nil {
				t.Fatalf("turn %d frame %d: %v", i, frames, err)
			}
			if ok {
				t.Fatalf("turn %d frame %d uses the packet stream channel", i, frames)
			}
			if len(packet.data) == 0 {
				t.Fatalf("turn %d frame %d has no channel", i, frames)
			}
			frames++
		}
	}
}

func TestRunPaddingScheduleLeavesPeerTurnsAlone(t *testing.T) {
	schedule := []paddingTurn{
		{direction: paddingClientToServer, minLength: 44, maxLength: 44},
		{direction: paddingServerToClient, minLength: 64, maxLength: 64},
		{direction: paddingClientToServer, minLength: 25, maxLength: 25},
	}

	var out bytes.Buffer
	if err := runPaddingSchedule(&out, true, 2, schedule); err != nil {
		t.Fatal(err)
	}

	reader := bytes.NewReader(out.Bytes())
	total := 0
	for reader.Len() > 0 {
		before := reader.Len()
		packet, err := readPacket(reader)
		if err != nil {
			t.Fatalf("padding stream is not a valid packet stream: %v", err)
		}
		if packet.packetID != configurationServerboundCustomPayload {
			t.Fatalf("unexpected packet id %d in padding stream", packet.packetID)
		}
		total += before - reader.Len()
	}
	// Turn 0 carries the 2 byte Login Acknowledged prefix, turn 1 is the peer's.
	want := 44 - 2 + 25
	if total != want {
		t.Fatalf("padding stream carries %d payload bytes, want %d", total, want)
	}
}

func TestRunPaddingScheduleRejectsInvalidSchedule(t *testing.T) {
	schedule := []paddingTurn{
		{direction: paddingServerToClient, minLength: 10, maxLength: 10},
	}
	if err := runPaddingSchedule(&bytes.Buffer{}, true, 2, schedule); err == nil {
		t.Fatal("expected an error for a prefixed server-to-client first turn")
	}
}
