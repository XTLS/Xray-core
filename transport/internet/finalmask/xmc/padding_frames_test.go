package xmc

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
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
		written, err := writePaddingTurnFrames(&buffer, turn, 0, noPaddingPause, configurationServerboundCustomPayload)
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
	if err := runPaddingSchedule(&out, true, 2, schedule, noPaddingPause); err != nil {
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
	if err := runPaddingSchedule(&bytes.Buffer{}, true, 2, schedule, noPaddingPause); err == nil {
		t.Fatal("expected an error for a prefixed server-to-client first turn")
	}
}

func noPaddingPause(time.Duration) error { return nil }

func TestRunPaddingScheduleWithoutTurns(t *testing.T) {
	var out bytes.Buffer
	if err := runPaddingSchedule(&out, true, 2, nil, noPaddingPause); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("disabled padding wrote %d bytes", out.Len())
	}
}

func TestRunPaddingScheduleStopsWhenClosed(t *testing.T) {
	schedule := []paddingTurn{
		{direction: paddingClientToServer, minLength: 44, maxLength: 44, delay: millisecondRange(1000, 1000)},
		{direction: paddingClientToServer, minLength: 44, maxLength: 44},
	}

	var out bytes.Buffer
	pauses := 0
	sleep := func(d time.Duration) error {
		if d <= 0 {
			return nil
		}
		pauses++
		return net.ErrClosed
	}
	err := runPaddingSchedule(&out, true, 2, schedule, sleep)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed, got %v", err)
	}
	if pauses != 1 {
		t.Fatalf("pauses = %d, want 1", pauses)
	}
	// The pause leads into turn 0, so the cancelled pause came before its bytes.
	if out.Len() != 0 {
		t.Fatalf("schedule kept writing after a cancelled pause: %d bytes", out.Len())
	}
}

// recordingWriter records one event per write, so a test can see where the
// pauses fall relative to the padding bytes.
type recordingWriter struct {
	events *[]string
}

func (w recordingWriter) Write(p []byte) (int, error) {
	*w.events = append(*w.events, "write")
	return len(p), nil
}

// TestPaddingDelayLeadsIntoTheTurn pins the placement of a configured pause:
// it belongs to the turn it precedes, the peer spends its minimum at the same
// place, and the last turn is not followed by one.
func TestPaddingDelayLeadsIntoTheTurn(t *testing.T) {
	schedule := []paddingTurn{
		{direction: paddingClientToServer, minLength: 44, maxLength: 44, delay: millisecondRange(10, 10)},
		{direction: paddingServerToClient, minLength: 20, maxLength: 20, delay: millisecondRange(20, 20)},
		{direction: paddingClientToServer, minLength: 44, maxLength: 44, delay: millisecondRange(30, 30)},
	}
	run := func(isClient bool) []string {
		var events []string
		sleep := func(d time.Duration) error {
			if d > 0 {
				events = append(events, "pause "+d.String())
			}
			return nil
		}
		if err := runPaddingSchedule(recordingWriter{events: &events}, isClient, 2, schedule, sleep); err != nil {
			t.Fatal(err)
		}
		return events
	}

	// The client sends turns 0 and 2, so it pauses before each of them and
	// spends the minimum of turn 1 while the server sends it.
	client := strings.Join(run(true), ",")
	wantClient := "pause 10ms,write,pause 20ms,pause 30ms,write"
	if client != wantClient {
		t.Fatalf("client events = %q, want %q", client, wantClient)
	}

	// The server sends turn 1, so the same pauses lead into its bytes. The last
	// turn's pause still happens, but nothing follows the final write.
	server := strings.Join(run(false), ",")
	wantServer := "pause 10ms,pause 20ms,write,pause 30ms"
	if server != wantServer {
		t.Fatalf("server events = %q, want %q", server, wantServer)
	}
}

// TestPaddingDelayRangeJittersOnlyTheSender pins which value each end waits:
// the side that sends the turn samples the range, the peer spends the minimum.
func TestPaddingDelayRangeJittersOnlyTheSender(t *testing.T) {
	schedule := []paddingTurn{
		{direction: paddingClientToServer, minLength: 44, maxLength: 44, delay: millisecondRange(20, 200)},
		{direction: paddingClientToServer, minLength: 44, maxLength: 44},
	}
	run := func(isClient bool) []time.Duration {
		var pauses []time.Duration
		sleep := func(d time.Duration) error {
			if d > 0 {
				pauses = append(pauses, d)
			}
			return nil
		}
		if err := runPaddingSchedule(io.Discard, isClient, 2, schedule, sleep); err != nil {
			t.Fatal(err)
		}
		return pauses
	}

	// The peer, which sends nothing here, spends exactly the minimum.
	if got := run(false); len(got) != 1 || got[0] != 20*time.Millisecond {
		t.Fatalf("peer pauses = %v, want exactly [20ms]", got)
	}

	seenLarge := false
	for i := 0; i < 64; i++ {
		pauses := run(true)
		if len(pauses) != 1 {
			t.Fatalf("sender pauses = %v, want exactly one pause", pauses)
		}
		if pauses[0] < 20*time.Millisecond || pauses[0] > 200*time.Millisecond {
			t.Fatalf("sender pause %s is outside the configured range", pauses[0])
		}
		if pauses[0] >= 20*time.Millisecond && pauses[0] <= 200*time.Millisecond && pauses[0] != 20*time.Millisecond {
			seenLarge = true
		}
	}
	if !seenLarge {
		t.Fatal("the sender never sampled a value above the minimum")
	}
}

func TestPaddingPauseReturnsOnClose(t *testing.T) {
	done := make(chan struct{})
	close(done)
	started := time.Now()
	if err := pausePadding(done, time.Hour); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed, got %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("pausePadding did not return on close")
	}
}
