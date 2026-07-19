package xmc

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPaddingTurnReachesFinalTargetLength(t *testing.T) {
	turn := paddingTurn{direction: paddingClientToServer, minLength: 128, maxLength: 128}
	const prefixLength = 3
	var encoded bytes.Buffer
	if err := writePaddingTurn(&encoded, turn, prefixLength); err != nil {
		t.Fatal(err)
	}
	if got := prefixLength + encoded.Len(); got != turn.minLength {
		t.Fatalf("total turn length = %d, want %d", got, turn.minLength)
	}
	encodedReader := bytes.NewReader(encoded.Bytes())
	var recordLength Varint
	if err := recordLength.readFrom(encodedReader); err != nil {
		t.Fatal(err)
	}
	if got := int(recordLength); got != encoded.Len() {
		t.Fatalf("record length = %d, encoded = %d", got, encoded.Len())
	}
	if err := readPaddingTurn(bytes.NewReader(encoded.Bytes()), turn, prefixLength); err != nil {
		t.Fatal(err)
	}
}

func TestPaddingTurnSupportsThreeByteTarget(t *testing.T) {
	turn := paddingTurn{direction: paddingClientToServer, minLength: 3, maxLength: 3}
	var encoded bytes.Buffer
	if err := writePaddingTurn(&encoded, turn, 0); err != nil {
		t.Fatal(err)
	}
	if got := encoded.Len(); got != 3 {
		t.Fatalf("padding length = %d, want 3", got)
	}
	if err := readPaddingTurn(bytes.NewReader(encoded.Bytes()), turn, 0); err != nil {
		t.Fatal(err)
	}
}

func TestPaddingTurnVarintBoundaries(t *testing.T) {
	for _, targetLength := range []int{127, 128, 16383, 16384} {
		t.Run(strconv.Itoa(targetLength), func(t *testing.T) {
			turn := paddingTurn{direction: paddingClientToServer, minLength: targetLength, maxLength: targetLength}
			var encoded bytes.Buffer
			if err := writePaddingTurn(&encoded, turn, 0); err != nil {
				t.Fatal(err)
			}
			if encoded.Len() != targetLength {
				t.Fatalf("padding length = %d, want %d", encoded.Len(), targetLength)
			}
			if err := readPaddingTurn(bytes.NewReader(encoded.Bytes()), turn, 0); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPaddingTurnRandomRange(t *testing.T) {
	turn := paddingTurn{direction: paddingServerToClient, minLength: 127, maxLength: 129}
	seen := make(map[int]bool)
	for range 100 {
		var encoded bytes.Buffer
		if err := writePaddingTurn(&encoded, turn, 0); err != nil {
			t.Fatal(err)
		}
		if encoded.Len() < turn.minLength || encoded.Len() > turn.maxLength {
			t.Fatalf("padding length = %d", encoded.Len())
		}
		seen[encoded.Len()] = true
	}
	if len(seen) < 2 {
		t.Fatalf("padding range did not vary: %v", seen)
	}
}

func TestPaddingTurnUsesRestrictedSendRange(t *testing.T) {
	turn := paddingTurn{
		direction:     paddingServerToClient,
		minLength:     3,
		maxLength:     100,
		sendMinLength: 90,
		sendMaxLength: 100,
	}
	seen := make(map[int]bool)
	for range 100 {
		var encoded bytes.Buffer
		if err := writePaddingTurn(&encoded, turn, 0); err != nil {
			t.Fatal(err)
		}
		if encoded.Len() < turn.sendMinLength || encoded.Len() > turn.sendMaxLength {
			t.Fatalf("padding length = %d", encoded.Len())
		}
		seen[encoded.Len()] = true
		if err := readPaddingTurn(bytes.NewReader(encoded.Bytes()), turn, 0); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) < 2 {
		t.Fatalf("restricted send range did not vary: %v", seen)
	}
}

func TestPaddingScheduleSynchronizesDirections(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	schedule := []paddingTurn{
		{direction: paddingClientToServer, minLength: 33, maxLength: 33},
		{direction: paddingServerToClient, minLength: 4097, maxLength: 4097},
		{direction: paddingClientToServer, minLength: 16385, maxLength: 16385},
	}
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- runPaddingSchedule(server, server, false, 3, schedule)
	}()
	if err := runPaddingSchedule(client, client, true, 3, schedule); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server padding schedule did not complete")
	}
}

func TestReadPaddingTurnHandlesFragmentedInput(t *testing.T) {
	turn := paddingTurn{direction: paddingClientToServer, minLength: 1024, maxLength: 1024}
	var encoded bytes.Buffer
	if err := writePaddingTurn(&encoded, turn, 0); err != nil {
		t.Fatal(err)
	}
	if err := readPaddingTurn(&oneByteReader{reader: bytes.NewReader(encoded.Bytes())}, turn, 0); err != nil {
		t.Fatal(err)
	}
}

func TestReadPaddingTurnRejectsInvalidLength(t *testing.T) {
	turn := paddingTurn{direction: paddingClientToServer, minLength: 64, maxLength: 96}
	data := encodePaddingLength(t, 63)
	if err := readPaddingTurn(bytes.NewReader(data), turn, 0); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("error = %v", err)
	}
}

func TestReadPaddingTurnRejectsNonCanonicalHeader(t *testing.T) {
	turn := paddingTurn{direction: paddingClientToServer, minLength: 3, maxLength: 3}
	err := readPaddingTurn(bytes.NewReader([]byte{0x83, 0x00, 0x00}), turn, 0)
	if err == nil || !strings.Contains(err.Error(), "non-canonical") {
		t.Fatalf("error = %v", err)
	}
}

func TestReadPaddingTurnRejectsTruncatedBody(t *testing.T) {
	turn := paddingTurn{direction: paddingClientToServer, minLength: 64, maxLength: 64}
	data := encodePaddingLength(t, 64)
	if err := readPaddingTurn(bytes.NewReader(data), turn, 0); err == nil || !strings.Contains(err.Error(), "body") {
		t.Fatalf("error = %v", err)
	}
}

func TestReadPaddingTurnHonorsConnectionTimeout(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	if err := server.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	turn := paddingTurn{direction: paddingClientToServer, minLength: 64, maxLength: 64}
	err := readPaddingTurn(server, turn, 0)
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("error = %v, want network timeout", err)
	}
}

func TestValidatePaddingSchedule(t *testing.T) {
	tests := []struct {
		name     string
		schedule []paddingTurn
		prefix   int
	}{
		{name: "empty"},
		{name: "bad direction", schedule: []paddingTurn{{direction: 99, minLength: 4, maxLength: 4}}},
		{name: "too small", schedule: []paddingTurn{{direction: paddingClientToServer, minLength: 0, maxLength: 4}}},
		{name: "reversed range", schedule: []paddingTurn{{direction: paddingClientToServer, minLength: 8, maxLength: 7}}},
		{name: "wrong first direction", prefix: 3, schedule: []paddingTurn{{direction: paddingServerToClient, minLength: 8, maxLength: 8}}},
		{name: "prefix leaves no header", prefix: 8, schedule: []paddingTurn{{direction: paddingClientToServer, minLength: 8, maxLength: 8}}},
		{name: "same direction", schedule: []paddingTurn{{direction: paddingClientToServer, minLength: 8, maxLength: 8}, {direction: paddingClientToServer, minLength: 8, maxLength: 8}}},
		{name: "range with variants", schedule: []paddingTurn{{direction: paddingClientToServer, minLength: 8, maxLength: 8, variants: []paddingVariant{paddingVariantFromChunks(8)}}}},
		{name: "empty variant", schedule: []paddingTurn{{direction: paddingClientToServer, variants: []paddingVariant{{}}}}},
		{name: "bad chunk", schedule: []paddingTurn{{direction: paddingClientToServer, variants: []paddingVariant{paddingVariantFromChunks(maxPaddingChunkLength + 1)}}}},
		{
			name: "delay mismatch",
			schedule: []paddingTurn{{
				direction: paddingClientToServer,
				variants: []paddingVariant{{
					chunks: []int{4, 4},
					delays: []paddingDelayRange{{min: time.Millisecond, max: time.Millisecond}},
				}},
			}},
		},
		{name: "reversed start delay", schedule: []paddingTurn{{direction: paddingClientToServer, minLength: 8, maxLength: 8, startDelay: paddingDelayRange{min: 2 * time.Millisecond, max: time.Millisecond}}}},
		{name: "reversed generated chunk delay", schedule: []paddingTurn{{direction: paddingClientToServer, minLength: 8, maxLength: 8, chunkDelay: paddingDelayRange{min: 2 * time.Millisecond, max: time.Millisecond}}}},
		{name: "oversized generated chunk", schedule: []paddingTurn{{direction: paddingClientToServer, minLength: 8, maxLength: 8, writeChunkLength: maxPaddingChunkLength + 1}}},
		{name: "reversed generated chunk range", schedule: []paddingTurn{{direction: paddingClientToServer, minLength: 8, maxLength: 8, writeChunkMinLength: 9, writeChunkLength: 8}}},
		{name: "variant with generated chunks", schedule: []paddingTurn{{direction: paddingClientToServer, variants: []paddingVariant{paddingVariantFromChunks(8)}, writeChunkLength: 8}}},
		{name: "send range outside accepted range", schedule: []paddingTurn{{direction: paddingClientToServer, minLength: 8, maxLength: 16, sendMinLength: 7, sendMaxLength: 12}}},
		{name: "variant with send range", schedule: []paddingTurn{{direction: paddingClientToServer, variants: []paddingVariant{paddingVariantFromChunks(8)}, sendMinLength: 8, sendMaxLength: 8}}},
		{name: "negative chunk delay", schedule: []paddingTurn{{direction: paddingClientToServer, variants: []paddingVariant{{chunks: []int{8}, delays: []paddingDelayRange{{min: -time.Millisecond}}}}}}},
		{name: "bad send variant", schedule: []paddingTurn{{direction: paddingClientToServer, variants: []paddingVariant{paddingVariantFromChunks(8)}, sendVariants: []int{1}}}},
		{name: "prefix splits chunk", prefix: 3, schedule: []paddingTurn{{direction: paddingClientToServer, variants: []paddingVariant{paddingVariantFromChunks(8, 4)}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validatePaddingSchedule(test.schedule, test.prefix); err == nil {
				t.Fatal("expected invalid padding schedule")
			}
		})
	}
}

func TestPaddingSchedule2612MatchesCapturedTemplates(t *testing.T) {
	wantDirections := []paddingDirection{
		paddingClientToServer,
		paddingServerToClient,
		paddingClientToServer,
		paddingServerToClient,
		paddingClientToServer,
		paddingServerToClient,
	}
	wantLengths := [][]int{
		{44},
		{72},
		{25},
		{41172},
		{2},
		{7464, 8267, 8790, 8153, 7375, 7347, 8184, 6633, 7670, 8241, 7857, 7254, 8407, 8283, 6804, 8177, 8177, 7929, 8296, 8177},
	}
	if len(paddingSchedule2612) != len(wantDirections)+33 {
		t.Fatalf("padding schedule has %d turns, want %d", len(paddingSchedule2612), len(wantDirections)+33)
	}
	for i, turn := range paddingSchedule2612[:len(wantDirections)] {
		if turn.direction != wantDirections[i] {
			t.Fatalf("padding turn %d direction = %d, want %d", i, turn.direction, wantDirections[i])
		}
		if len(turn.variants) != len(wantLengths[i]) {
			t.Fatalf("padding turn %d has %d variants, want %d", i, len(turn.variants), len(wantLengths[i]))
		}
		for j, variant := range turn.variants {
			if got := paddingVariantLength(variant); got != wantLengths[i][j] {
				t.Fatalf("padding turn %d variant %d length = %d, want %d", i, j, got, wantLengths[i][j])
			}
		}
	}
	wantPlayBounds := [][2]int{
		{6, 883}, {346, 58638}, {6, 887}, {388, 61077}, {2, 50}, {575, 65584},
		{6, 45}, {86, 63563}, {2, 44}, {42, 51983}, {2, 851}, {309, 25083},
		{2, 19}, {74, 63885}, {8, 24}, {30, 66128}, {2, 19}, {26, 35818},
		{6, 19}, {35, 59407}, {6, 19}, {37, 65328}, {2, 19}, {26, 60622},
		{6, 19}, {11, 60808}, {8, 43}, {55, 62027}, {2, 19}, {427, 65622},
		{5, 19}, {35, 59401}, {6, 19},
	}
	for i, want := range wantPlayBounds {
		turn := paddingSchedule2612[len(wantDirections)+i]
		wantDirection := paddingClientToServer
		if i%2 == 1 {
			wantDirection = paddingServerToClient
		}
		if turn.direction != wantDirection {
			t.Fatalf("play turn %d direction = %d, want %d", i, turn.direction, wantDirection)
		}
		if turn.minLength != want[0] || turn.maxLength != want[1] {
			t.Fatalf("play turn %d bounds = %d-%d, want %d-%d", i, turn.minLength, turn.maxLength, want[0], want[1])
		}
		if len(turn.variants) != 0 {
			t.Fatalf("play turn %d unexpectedly has captured variants", i)
		}
	}
	if got := len(paddingSchedule2612[3].variants[0].chunks); got != 30 {
		t.Fatalf("registry turn chunks = %d, want 30", got)
	}
	minimumPlayStart := maxPaddingTurnLength
	maximumPlayStart := 0
	for _, variant := range paddingSchedule2612[5].variants {
		length := paddingVariantLength(variant)
		minimumPlayStart = min(minimumPlayStart, length)
		maximumPlayStart = max(maximumPlayStart, length)
		if variant.chunks[0] != 4941 {
			t.Fatalf("play start first chunk = %d, want 4941", variant.chunks[0])
		}
	}
	if minimumPlayStart != 6633 || maximumPlayStart != 8790 {
		t.Fatalf("play start bounds = %d-%d, want 6633-8790", minimumPlayStart, maximumPlayStart)
	}
	if err := validatePaddingSchedule(paddingSchedule2612, 2); err != nil {
		t.Fatalf("captured schedule is invalid: %v", err)
	}

	serverSchedule, err := newServerPaddingSchedule2612()
	if err != nil {
		t.Fatal(err)
	}
	if err = validatePaddingSchedule(serverSchedule, 2); err != nil {
		t.Fatalf("server schedule is invalid: %v", err)
	}
	for i, branches := range serverPlayBranches2612 {
		turn := serverSchedule[len(startupPaddingSchedule2612)+1+i*2]
		got := paddingLengthRange2612{turn.sendMinLength, turn.sendMaxLength}
		if got != branches.small && got != branches.large {
			t.Fatalf("server play turn %d send range = %v, want %v or %v", i, got, branches.small, branches.large)
		}
	}

	for range 20 {
		clientSchedule, clientErr := newClientPaddingSchedule2612()
		if clientErr != nil {
			t.Fatal(clientErr)
		}
		if clientErr = validatePaddingSchedule(clientSchedule, 2); clientErr != nil {
			t.Fatalf("client schedule is invalid: %v", clientErr)
		}
		burstCount := 0
		for _, burst := range clientPlayBursts2612 {
			turn := clientSchedule[len(startupPaddingSchedule2612)+burst.playIndex]
			got := paddingLengthRange2612{turn.sendMinLength, turn.sendMaxLength}
			switch got {
			case burst.regular:
			case burst.burst:
				burstCount++
			default:
				t.Fatalf("client play turn %d send range = %v", burst.playIndex, got)
			}
		}
		if burstCount != 1 {
			t.Fatalf("client schedule has %d initialization bursts, want 1", burstCount)
		}
	}

	for variantIndex := range paddingSchedule2612[3].variants {
		turn := paddingSchedule2612[3]
		turn.sendVariants = []int{variantIndex}
		var encoded bytes.Buffer
		if err = writePaddingTurnWithSleep(&encoded, turn, 0, func(time.Duration) {}); err != nil {
			t.Fatal(err)
		}
		if err = readPaddingTurn(bytes.NewReader(encoded.Bytes()), paddingSchedule2612[3], 0); err != nil {
			t.Fatalf("registry variant %d was rejected: %v", variantIndex, err)
		}
	}
}

func TestPaddingVariantPreservesWriteBoundaries(t *testing.T) {
	tests := []struct {
		name   string
		turn   paddingTurn
		prefix int
		want   []int
	}{
		{name: "login acknowledged turn", turn: paddingSchedule2612[0], prefix: 2, want: []int{26, 16}},
		{name: "server response turn", turn: paddingSchedule2612[1], want: []int{26, 21, 25}},
		{name: "single packet turn", turn: paddingSchedule2612[2], want: []int{25}},
		{name: "fixed registry profile", turn: paddingSchedule2612[3], want: paddingSchedule2612[3].variants[0].chunks},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var writer recordingWriter
			if err := writePaddingTurnWithSleep(&writer, test.turn, test.prefix, func(time.Duration) {}); err != nil {
				t.Fatal(err)
			}
			if len(writer.writes) != len(test.want) {
				t.Fatalf("writes = %v, want %v", writer.writes, test.want)
			}
			for i := range test.want {
				if writer.writes[i] != test.want[i] {
					t.Fatalf("writes = %v, want %v", writer.writes, test.want)
				}
			}
			if err := readPaddingTurn(bytes.NewReader(writer.Bytes()), test.turn, test.prefix); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPaddingVariantAppliesPacing(t *testing.T) {
	turn := paddingTurn{
		direction:  paddingClientToServer,
		startDelay: paddingDelayRange{min: 3 * time.Millisecond, max: 3 * time.Millisecond},
		variants: []paddingVariant{{
			chunks: []int{3, 5, 7},
			delays: []paddingDelayRange{
				{},
				{min: 2 * time.Millisecond, max: 2 * time.Millisecond},
				{min: 4 * time.Millisecond, max: 4 * time.Millisecond},
			},
		}},
	}
	var slept []time.Duration
	var writer recordingWriter
	if err := writePaddingTurnWithSleep(&writer, turn, 3, func(delay time.Duration) {
		slept = append(slept, delay)
	}); err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{3 * time.Millisecond, 2 * time.Millisecond, 4 * time.Millisecond}
	if len(slept) != len(want) {
		t.Fatalf("delays = %v, want %v", slept, want)
	}
	for i := range want {
		if slept[i] != want[i] {
			t.Fatalf("delays = %v, want %v", slept, want)
		}
	}
}

func TestGeneratedPaddingChunksApplyPacing(t *testing.T) {
	turn := paddingTurn{
		direction:        paddingServerToClient,
		minLength:        100,
		maxLength:        100,
		writeChunkLength: 32,
		chunkDelay:       paddingDelayRange{min: 2 * time.Millisecond, max: 2 * time.Millisecond},
	}
	var slept []time.Duration
	var writer recordingWriter
	if err := writePaddingTurnWithSleep(&writer, turn, 0, func(delay time.Duration) {
		slept = append(slept, delay)
	}); err != nil {
		t.Fatal(err)
	}
	wantWrites := []int{32, 32, 32, 4}
	if !slicesEqual(writer.writes, wantWrites) {
		t.Fatalf("writes = %v, want %v", writer.writes, wantWrites)
	}
	wantSleeps := []time.Duration{2 * time.Millisecond, 2 * time.Millisecond, 2 * time.Millisecond}
	if !slicesEqual(slept, wantSleeps) {
		t.Fatalf("delays = %v, want %v", slept, wantSleeps)
	}
	if err := readPaddingTurn(bytes.NewReader(writer.Bytes()), turn, 0); err != nil {
		t.Fatal(err)
	}
}

func TestGeneratedPaddingChunkLengthIsRandomized(t *testing.T) {
	turn := paddingTurn{
		direction:           paddingServerToClient,
		minLength:           100,
		maxLength:           100,
		writeChunkMinLength: 16,
		writeChunkLength:    32,
	}
	seen := make(map[int]bool)
	for range 100 {
		var writer recordingWriter
		if err := writePaddingTurnWithSleep(&writer, turn, 0, func(time.Duration) {}); err != nil {
			t.Fatal(err)
		}
		firstWrite := writer.writes[0]
		if firstWrite < turn.writeChunkMinLength || firstWrite > turn.writeChunkLength {
			t.Fatalf("first write = %d", firstWrite)
		}
		seen[firstWrite] = true
	}
	if len(seen) < 2 {
		t.Fatalf("generated write chunk length did not vary: %v", seen)
	}
}

func TestPaddingDelayRangeIsRandomized(t *testing.T) {
	delayRange := millisecondRange(25, 40)
	seen := make(map[time.Duration]bool)
	for range 100 {
		delay, err := randomPaddingDelay(delayRange)
		if err != nil {
			t.Fatal(err)
		}
		if delay < delayRange.min || delay > delayRange.max {
			t.Fatalf("delay = %s, want %s-%s", delay, delayRange.min, delayRange.max)
		}
		seen[delay] = true
	}
	if len(seen) < 2 {
		t.Fatalf("padding delay did not vary: %v", seen)
	}
}

func TestPaddingSchedule2612UsesCoarseTimingBands(t *testing.T) {
	assertDelayRange(t, "turn 3 to 4", paddingSchedule2612[3].startDelay, 20*time.Millisecond, 50*time.Millisecond)
	assertDelayRange(t, "turn 5 to 6", paddingSchedule2612[5].startDelay, 35*time.Millisecond, 50*time.Millisecond)
	assertDelayRange(t, "first play client turn", paddingSchedule2612[6].startDelay, time.Millisecond, 30*time.Millisecond)
	assertDelayRange(t, "first play server turn", paddingSchedule2612[7].startDelay, time.Millisecond, 45*time.Millisecond)
	assertDelayRange(t, "play server chunk pacing", paddingSchedule2612[7].chunkDelay, time.Millisecond, 4*time.Millisecond)
	if paddingSchedule2612[6].writeChunkLength != 1024 {
		t.Fatalf("play client write chunk = %d, want 1024", paddingSchedule2612[6].writeChunkLength)
	}
	if paddingSchedule2612[7].writeChunkLength != maxPaddingChunkLength {
		t.Fatalf("play server write chunk = %d, want %d", paddingSchedule2612[7].writeChunkLength, maxPaddingChunkLength)
	}
	if paddingSchedule2612[7].writeChunkMinLength != 32*1024 {
		t.Fatalf("play server minimum write chunk = %d, want %d", paddingSchedule2612[7].writeChunkMinLength, 32*1024)
	}

	for i, variant := range paddingSchedule2612[3].variants {
		minimum, maximum := paddingVariantDelayBounds(variant)
		if minimum != 45*time.Millisecond || maximum != 65*time.Millisecond {
			t.Fatalf("turn 4 variant %d duration = %s-%s, want 45ms-65ms", i, minimum, maximum)
		}
	}
	for i, variant := range paddingSchedule2612[5].variants {
		minimum, maximum := paddingVariantDelayBounds(variant)
		if minimum != 10*time.Millisecond || maximum != 25*time.Millisecond {
			t.Fatalf("turn 6 variant %d duration = %s-%s, want 10ms-25ms", i, minimum, maximum)
		}
	}
}

func assertDelayRange(t *testing.T, name string, got paddingDelayRange, minimum, maximum time.Duration) {
	t.Helper()
	if got.min != minimum || got.max != maximum {
		t.Fatalf("%s delay = %s-%s, want %s-%s", name, got.min, got.max, minimum, maximum)
	}
}

func paddingVariantDelayBounds(variant paddingVariant) (time.Duration, time.Duration) {
	var minimum time.Duration
	var maximum time.Duration
	for _, delay := range variant.delays {
		minimum += delay.min
		maximum += delay.max
	}
	return minimum, maximum
}

func slicesEqual[T comparable](left, right []T) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func encodePaddingLength(t *testing.T, length int) []byte {
	t.Helper()
	var encoded bytes.Buffer
	value := Varint(length)
	if err := value.writeTo(&encoded); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}

type oneByteReader struct {
	reader io.Reader
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.reader.Read(p)
}

type recordingWriter struct {
	bytes.Buffer
	writes []int
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	w.writes = append(w.writes, len(p))
	return w.Buffer.Write(p)
}
