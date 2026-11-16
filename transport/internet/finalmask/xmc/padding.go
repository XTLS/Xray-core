package xmc

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"time"
)

type paddingDirection uint8

const (
	paddingClientToServer paddingDirection = iota + 1
	paddingServerToClient

	paddingBufferLength   = 16 * 1024
	maxPaddingChunkLength = 48 * 1024
	maxPaddingTurnLength  = 8 * 1024 * 1024

	// Frame padding carries the startup padding in ordinary Minecraft custom
	// payload packets so that a vanilla server can parse the whole connection
	// without taking the pipeline over. The channel is deliberately different
	// from the packet stream channel: both ends drop unknown payloads.
	paddingFrameChannel = "xmc:pad"
	// Serverbound custom payload data is capped at 32767 bytes by
	// ServerboundCustomPayloadPacket; keep the same budget in both directions.
	maxPaddingFrameDataLength = 32767
	// Length varint, packet id, channel length varint and the channel itself.
	paddingFrameOverhead = 1 + 1 + 1 + len(paddingFrameChannel)
)

var maxPaddingFrameLength = paddingFrameLength(maxPaddingFrameDataLength)

type paddingVariant struct {
	chunks []int
	delays []paddingDelayRange
}

type paddingDelayRange struct {
	min time.Duration
	max time.Duration
}

type paddingTurn struct {
	direction           paddingDirection
	minLength           int
	maxLength           int
	delay               paddingDelayRange // pause after this turn, including the last one
	variants            []paddingVariant
	startDelay          paddingDelayRange
	chunkDelay          paddingDelayRange
	writeChunkMinLength int
	writeChunkLength    int
	sendMinLength       int
	sendMaxLength       int
	sendVariants        []int
}

func runPaddingSchedule(writer io.Writer, isClient bool, firstTurnPrefixLength int, schedule []paddingTurn) error {
	return runPaddingScheduleWithSleep(writer, isClient, firstTurnPrefixLength, schedule, time.Sleep)
}

func runPaddingScheduleWithSleep(writer io.Writer, isClient bool, firstTurnPrefixLength int, schedule []paddingTurn, sleep func(time.Duration)) error {
	if err := validatePaddingSchedule(schedule, firstTurnPrefixLength); err != nil {
		return err
	}

	for i, turn := range schedule {
		prefixLength := 0
		if i == 0 {
			prefixLength = firstTurnPrefixLength
		}

		if isClient != (turn.direction == paddingClientToServer) {
			// Padding is ordinary Minecraft traffic, so the peer's turns are
			// never consumed here: they stay in the stream and are dropped as
			// unknown packets by whoever reads it next. Both endpoints still
			// apply the same minimum pause, including after the last turn.
			if turn.delay.min > 0 {
				sleep(turn.delay.min)
			}
			continue
		}
		if _, err := writePaddingTurnFrames(writer, turn, prefixLength, sleep, paddingFramePacketID(isClient)); err != nil {
			return fmt.Errorf("write padding turn %d: %w", i, err)
		}
		delay, err := randomPaddingDelay(turn.delay)
		if err != nil {
			return fmt.Errorf("select padding turn %d delay: %w", i, err)
		}
		if delay > 0 {
			sleep(delay)
		}
	}
	return nil
}

func validatePaddingSchedule(schedule []paddingTurn, firstTurnPrefixLength int) error {
	if len(schedule) == 0 {
		return fmt.Errorf("empty padding schedule")
	}
	if firstTurnPrefixLength < 0 {
		return fmt.Errorf("negative first turn prefix length: %d", firstTurnPrefixLength)
	}
	if firstTurnPrefixLength > 0 && schedule[0].direction != paddingClientToServer {
		return fmt.Errorf("first prefixed padding turn is not client-to-server")
	}

	for i, turn := range schedule {
		if turn.direction != paddingClientToServer && turn.direction != paddingServerToClient {
			return fmt.Errorf("padding turn %d has invalid direction: %d", i, turn.direction)
		}
		if err := validatePaddingDelayRange(turn.startDelay); err != nil {
			return fmt.Errorf("padding turn %d has an invalid start delay: %w", i, err)
		}
		if err := validatePaddingDelayRange(turn.chunkDelay); err != nil {
			return fmt.Errorf("padding turn %d has an invalid chunk delay: %w", i, err)
		}
		if err := validatePaddingDelayRange(turn.delay); err != nil {
			return fmt.Errorf("padding turn %d has an invalid inter-turn delay: %w", i, err)
		}
		if turn.writeChunkMinLength < 0 || turn.writeChunkLength < turn.writeChunkMinLength || turn.writeChunkLength > maxPaddingChunkLength {
			return fmt.Errorf("padding turn %d has an invalid write chunk range: %d-%d", i, turn.writeChunkMinLength, turn.writeChunkLength)
		}
		if len(turn.variants) > 0 && turn.writeChunkLength != 0 {
			return fmt.Errorf("padding turn %d combines variants with generated write chunks", i)
		}

		minLength, maxLength, err := paddingTurnBounds(turn)
		if err != nil {
			return fmt.Errorf("padding turn %d: %w", i, err)
		}
		hasSendRange := turn.sendMinLength != 0 || turn.sendMaxLength != 0
		if hasSendRange {
			if len(turn.variants) > 0 {
				return fmt.Errorf("padding turn %d combines variants with a send range", i)
			}
			if turn.sendMinLength < minLength || turn.sendMaxLength < turn.sendMinLength || turn.sendMaxLength > maxLength {
				return fmt.Errorf("padding turn %d has an invalid send range: %d-%d", i, turn.sendMinLength, turn.sendMaxLength)
			}
		}
		if i == 0 && minLength-firstTurnPrefixLength < 1 {
			return fmt.Errorf("padding turn 0 is too short for %d prefix bytes", firstTurnPrefixLength)
		}
		if i == 0 && len(turn.variants) > 0 {
			for j, variant := range turn.variants {
				if _, _, err = trimPaddingPrefix(variant, firstTurnPrefixLength); err != nil {
					return fmt.Errorf("padding turn 0 variant %d: %w", j, err)
				}
			}
		}
	}
	return nil
}

// paddingFramePacketID returns the configuration-state custom payload packet id
// used by the side that sends the padding bytes; both values come from the
// vanilla configuration protocol, so no proxy-specific id ever reaches the wire.
func paddingFramePacketID(isClient bool) int {
	if isClient {
		return configurationServerboundCustomPayload
	}
	return configurationClientboundCustomPayload
}

// writePaddingTurnFrames writes one padding turn as a sequence of valid
// Minecraft custom payload frames. Only the framing is native: payload bodies
// stay zero-filled, so the captured traffic shape is kept.
func writePaddingTurnFrames(w io.Writer, turn paddingTurn, prefixLength int, sleep func(time.Duration), packetID int) (int, error) {
	startDelay, err := randomPaddingDelay(turn.startDelay)
	if err != nil {
		return 0, fmt.Errorf("select padding start delay: %w", err)
	}
	if startDelay > 0 {
		sleep(startDelay)
	}

	targetLength, chunks, delays, err := selectPaddingVariant(turn, prefixLength)
	if err != nil {
		return 0, err
	}
	payloadLength := targetLength - prefixLength
	if payloadLength < 1 {
		return 0, fmt.Errorf("target length %d leaves an invalid padding payload of %d bytes", targetLength, payloadLength)
	}
	if len(chunks) == 0 {
		writeChunkLength := turn.writeChunkLength
		if writeChunkLength == 0 {
			writeChunkLength = paddingBufferLength
		} else if turn.writeChunkMinLength > 0 {
			writeChunkLength, err = randomPaddingTarget(turn.writeChunkMinLength, writeChunkLength)
			if err != nil {
				return 0, fmt.Errorf("select padding write chunk length: %w", err)
			}
		}
		chunks = defaultPaddingChunks(payloadLength, writeChunkLength)
		delays = make([]paddingDelayRange, len(chunks))
		for i := 1; i < len(delays); i++ {
			delays[i] = turn.chunkDelay
		}
	}

	zeros := make([]byte, maxPaddingFrameDataLength)
	channel := String(paddingFrameChannel)
	written := 0
	for i, chunkLength := range chunks {
		if i < len(delays) {
			delay, delayErr := randomPaddingDelay(delays[i])
			if delayErr != nil {
				return written, fmt.Errorf("select padding chunk %d delay: %w", i, delayErr)
			}
			if delay > 0 {
				sleep(delay)
			}
		}
		frameLengths, planErr := paddingFramePlan(chunkLength)
		if planErr != nil {
			return written, planErr
		}
		for _, frameLength := range frameLengths {
			dataLength, ok := paddingFrameDataLength(frameLength)
			if !ok {
				return written, fmt.Errorf("unframed padding length %d", frameLength)
			}
			payload := RestBytes(zeros[:dataLength])
			if err = writePacket(w, packetID, &channel, &payload); err != nil {
				return written, fmt.Errorf("write padding frame: %w", err)
			}
			written += frameLength
		}
	}
	return written, nil
}

// paddingFrameLength is the wire size of a custom payload frame whose payload
// body is dataLength bytes long.
func paddingFrameLength(dataLength int) int {
	bodyLength := 1 + 1 + len(paddingFrameChannel) + dataLength
	return varintSize(Varint(bodyLength)) + bodyLength
}

// paddingFrameDataLength is the payload body that makes a frame exactly
// frameLength bytes long. Some lengths are unreachable because the length
// varint grows in steps.
func paddingFrameDataLength(frameLength int) (int, bool) {
	for overhead := paddingFrameOverhead; overhead <= paddingFrameOverhead+2; overhead++ {
		dataLength := frameLength - overhead
		if dataLength < 0 || dataLength > maxPaddingFrameDataLength {
			continue
		}
		if paddingFrameLength(dataLength) == frameLength {
			return dataLength, true
		}
	}
	return 0, false
}

// paddingFramePlan splits length bytes into reachable frame sizes. The result is
// exact whenever a partition exists; a length below the smallest frame (the
// captured 2-byte turns) is rounded up to that frame.
func paddingFramePlan(length int) ([]int, error) {
	if length <= 0 {
		return nil, nil
	}
	if length < paddingFrameOverhead {
		return []int{paddingFrameOverhead}, nil
	}
	frameLengths := make([]int, 0, length/paddingBufferLength+1)
	for remaining := length; remaining > 0; {
		candidate := min(remaining, maxPaddingFrameLength)
		picked := 0
		for ; candidate >= paddingFrameOverhead; candidate-- {
			if _, ok := paddingFrameDataLength(candidate); !ok {
				continue
			}
			rest := remaining - candidate
			if rest > 0 && rest < paddingFrameOverhead {
				continue
			}
			picked = candidate
			break
		}
		if picked == 0 {
			return nil, fmt.Errorf("cannot frame %d padding bytes", length)
		}
		frameLengths = append(frameLengths, picked)
		remaining -= picked
	}
	return frameLengths, nil
}

func selectPaddingVariant(turn paddingTurn, prefixLength int) (int, []int, []paddingDelayRange, error) {
	if len(turn.variants) == 0 {
		minimum, maximum := turn.minLength, turn.maxLength
		if turn.sendMinLength != 0 || turn.sendMaxLength != 0 {
			minimum, maximum = turn.sendMinLength, turn.sendMaxLength
		}
		targetLength, err := randomPaddingTarget(minimum, maximum)
		return targetLength, nil, nil, err
	}

	indices := turn.sendVariants
	if len(indices) == 0 {
		indices = make([]int, len(turn.variants))
		for i := range indices {
			indices[i] = i
		}
	}
	selected, err := randomPaddingIndex(len(indices))
	if err != nil {
		return 0, nil, nil, err
	}
	variantIndex := indices[selected]
	if variantIndex < 0 || variantIndex >= len(turn.variants) {
		return 0, nil, nil, fmt.Errorf("invalid send variant index: %d", variantIndex)
	}
	variant := turn.variants[variantIndex]
	targetLength := paddingVariantLength(variant)
	chunks, delays, err := trimPaddingPrefix(variant, prefixLength)
	if err != nil {
		return 0, nil, nil, err
	}
	return targetLength, chunks, delays, nil
}

func trimPaddingPrefix(variant paddingVariant, prefixLength int) ([]int, []paddingDelayRange, error) {
	remainingPrefix := prefixLength
	firstChunk := 0
	for firstChunk < len(variant.chunks) && remainingPrefix > 0 {
		chunkLength := variant.chunks[firstChunk]
		if remainingPrefix < chunkLength {
			return nil, nil, fmt.Errorf("prefix length %d splits chunk %d", prefixLength, firstChunk)
		}
		remainingPrefix -= chunkLength
		firstChunk++
	}
	if remainingPrefix != 0 || firstChunk == len(variant.chunks) {
		return nil, nil, fmt.Errorf("prefix length %d leaves no padding record", prefixLength)
	}

	chunks := append([]int(nil), variant.chunks[firstChunk:]...)
	delays := make([]paddingDelayRange, len(chunks))
	if len(variant.delays) > 0 {
		copy(delays, variant.delays[firstChunk:])
	}
	return chunks, delays, nil
}

func defaultPaddingChunks(recordLength, writeChunkLength int) []int {
	chunks := make([]int, 0, (recordLength+writeChunkLength-1)/writeChunkLength)
	for remaining := recordLength; remaining > 0; {
		chunkLength := min(remaining, writeChunkLength)
		chunks = append(chunks, chunkLength)
		remaining -= chunkLength
	}
	return chunks
}

func paddingTurnBounds(turn paddingTurn) (int, int, error) {
	if len(turn.variants) == 0 {
		if turn.minLength < 1 || turn.maxLength < turn.minLength || turn.maxLength > maxPaddingTurnLength {
			return 0, 0, fmt.Errorf("invalid range: %d-%d", turn.minLength, turn.maxLength)
		}
		return turn.minLength, turn.maxLength, nil
	}
	if turn.minLength != 0 || turn.maxLength != 0 {
		return 0, 0, fmt.Errorf("variants cannot be combined with a length range")
	}

	minLength := maxPaddingTurnLength + 1
	maxLength := 0
	for i, variant := range turn.variants {
		if len(variant.chunks) == 0 {
			return 0, 0, fmt.Errorf("variant %d has no chunks", i)
		}
		if len(variant.delays) != 0 && len(variant.delays) != len(variant.chunks) {
			return 0, 0, fmt.Errorf("variant %d has %d chunks and %d delays", i, len(variant.chunks), len(variant.delays))
		}
		for j, chunkLength := range variant.chunks {
			if chunkLength < 1 || chunkLength > maxPaddingChunkLength {
				return 0, 0, fmt.Errorf("variant %d chunk %d has invalid length: %d", i, j, chunkLength)
			}
			if len(variant.delays) > 0 {
				if err := validatePaddingDelayRange(variant.delays[j]); err != nil {
					return 0, 0, fmt.Errorf("variant %d chunk %d has an invalid delay: %w", i, j, err)
				}
			}
		}
		length := paddingVariantLength(variant)
		if length > maxPaddingTurnLength {
			return 0, 0, fmt.Errorf("variant %d is too long: %d", i, length)
		}
		minLength = min(minLength, length)
		maxLength = max(maxLength, length)
	}
	for _, index := range turn.sendVariants {
		if index < 0 || index >= len(turn.variants) {
			return 0, 0, fmt.Errorf("invalid send variant index: %d", index)
		}
	}
	return minLength, maxLength, nil
}

func paddingTurnAcceptsLength(turn paddingTurn, length int) bool {
	if len(turn.variants) == 0 {
		return length >= turn.minLength && length <= turn.maxLength
	}
	for _, variant := range turn.variants {
		if paddingVariantLength(variant) == length {
			return true
		}
	}
	return false
}

func paddingVariantLength(variant paddingVariant) int {
	total := 0
	for _, chunkLength := range variant.chunks {
		total += chunkLength
	}
	return total
}

func validatePaddingDelayRange(delay paddingDelayRange) error {
	if delay.min < 0 || delay.max < delay.min {
		return fmt.Errorf("invalid range: %s-%s", delay.min, delay.max)
	}
	return nil
}

func randomPaddingDelay(delay paddingDelayRange) (time.Duration, error) {
	if err := validatePaddingDelayRange(delay); err != nil {
		return 0, err
	}
	if delay.min == delay.max {
		return delay.min, nil
	}
	span := int64(delay.max-delay.min) + 1
	offset, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return 0, fmt.Errorf("select padding delay: %w", err)
	}
	return delay.min + time.Duration(offset.Int64()), nil
}

func randomPaddingIndex(length int) (int, error) {
	if length < 1 {
		return 0, fmt.Errorf("select from empty padding choices")
	}
	if length == 1 {
		return 0, nil
	}
	index, err := rand.Int(rand.Reader, big.NewInt(int64(length)))
	if err != nil {
		return 0, fmt.Errorf("select padding choice: %w", err)
	}
	return int(index.Int64()), nil
}

func randomPaddingTarget(minLength, maxLength int) (int, error) {
	if minLength == maxLength {
		return minLength, nil
	}
	span := int64(maxLength-minLength) + 1
	offset, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return 0, fmt.Errorf("select padding length: %w", err)
	}
	return minLength + int(offset.Int64()), nil
}
