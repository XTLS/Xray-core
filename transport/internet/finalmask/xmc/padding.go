package xmc

import (
	"bytes"
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
)

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
	variants            []paddingVariant
	startDelay          paddingDelayRange
	chunkDelay          paddingDelayRange
	writeChunkMinLength int
	writeChunkLength    int
	sendMinLength       int
	sendMaxLength       int
	sendVariants        []int
}

func runPaddingSchedule(reader io.Reader, writer io.Writer, isClient bool, firstTurnPrefixLength int, schedule []paddingTurn) error {
	if err := validatePaddingSchedule(schedule, firstTurnPrefixLength); err != nil {
		return err
	}

	var writeBuffer []byte
	for i, turn := range schedule {
		prefixLength := 0
		if i == 0 {
			prefixLength = firstTurnPrefixLength
		}

		localSends := isClient == (turn.direction == paddingClientToServer)
		if localSends {
			if err := writePaddingTurnWithBuffer(writer, turn, prefixLength, time.Sleep, &writeBuffer); err != nil {
				return fmt.Errorf("write padding turn %d: %w", i, err)
			}
			continue
		}
		if err := readPaddingTurn(reader, turn, prefixLength); err != nil {
			return fmt.Errorf("read padding turn %d: %w", i, err)
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
		if i > 0 && turn.direction == schedule[i-1].direction {
			return fmt.Errorf("padding turns %d and %d have the same direction", i-1, i)
		}
	}
	return nil
}

func writePaddingTurn(w io.Writer, turn paddingTurn, prefixLength int) error {
	return writePaddingTurnWithSleep(w, turn, prefixLength, time.Sleep)
}

func writePaddingTurnWithSleep(w io.Writer, turn paddingTurn, prefixLength int, sleep func(time.Duration)) error {
	return writePaddingTurnWithBuffer(w, turn, prefixLength, sleep, nil)
}

func writePaddingTurnWithBuffer(w io.Writer, turn paddingTurn, prefixLength int, sleep func(time.Duration), reusableBuffer *[]byte) error {
	startDelay, err := randomPaddingDelay(turn.startDelay)
	if err != nil {
		return fmt.Errorf("select padding start delay: %w", err)
	}
	if startDelay > 0 {
		sleep(startDelay)
	}

	targetLength, chunks, delays, err := selectPaddingVariant(turn, prefixLength)
	if err != nil {
		return err
	}
	recordLength := targetLength - prefixLength
	if recordLength < 1 {
		return fmt.Errorf("target length %d leaves an invalid record length %d", targetLength, recordLength)
	}

	encodedLength := Varint(recordLength)
	var header bytes.Buffer
	if err = encodedLength.writeTo(&header); err != nil {
		return fmt.Errorf("write padding header: %w", err)
	}
	if len(chunks) == 0 {
		writeChunkLength := turn.writeChunkLength
		if writeChunkLength == 0 {
			writeChunkLength = paddingBufferLength
		} else if turn.writeChunkMinLength > 0 {
			writeChunkLength, err = randomPaddingTarget(turn.writeChunkMinLength, writeChunkLength)
			if err != nil {
				return fmt.Errorf("select padding write chunk length: %w", err)
			}
		}
		chunks = defaultPaddingChunks(recordLength, writeChunkLength)
		delays = make([]paddingDelayRange, len(chunks))
		for i := 1; i < len(delays); i++ {
			delays[i] = turn.chunkDelay
		}
	}
	if chunks[0] < header.Len() {
		return fmt.Errorf("first padding chunk %d is shorter than header %d", chunks[0], header.Len())
	}

	maxChunkLength := 0
	for _, chunkLength := range chunks {
		if chunkLength < 1 || chunkLength > maxPaddingChunkLength {
			return fmt.Errorf("invalid padding chunk length: %d", chunkLength)
		}
		maxChunkLength = max(maxChunkLength, chunkLength)
	}
	var buffer []byte
	if reusableBuffer == nil {
		buffer = make([]byte, maxChunkLength)
	} else {
		if cap(*reusableBuffer) < maxChunkLength {
			*reusableBuffer = make([]byte, maxChunkLength)
		}
		buffer = (*reusableBuffer)[:maxChunkLength]
		clear(buffer)
	}
	copy(buffer, header.Bytes())
	written := 0
	for i, chunkLength := range chunks {
		if i < len(delays) {
			delay, delayErr := randomPaddingDelay(delays[i])
			if delayErr != nil {
				return fmt.Errorf("select padding chunk %d delay: %w", i, delayErr)
			}
			if delay > 0 {
				sleep(delay)
			}
		}
		if err = writeFull(w, buffer[:chunkLength]); err != nil {
			return fmt.Errorf("write padding chunk %d: %w", i, err)
		}
		written += chunkLength
		if i == 0 {
			clear(buffer[:header.Len()])
		}
	}
	if written != recordLength {
		return fmt.Errorf("padding chunks total %d, want %d", written, recordLength)
	}
	return nil
}

func readPaddingTurn(r io.Reader, turn paddingTurn, prefixLength int) error {
	encodedLength, headerLength, err := readVarintWithLength(r)
	if err != nil {
		return fmt.Errorf("read padding header: %w", err)
	}
	recordLength := int(encodedLength)
	if recordLength < headerLength || recordLength > maxPaddingTurnLength {
		return fmt.Errorf("invalid padding record length: %d", recordLength)
	}
	totalLength := prefixLength + recordLength
	if !paddingTurnAcceptsLength(turn, totalLength) {
		if len(turn.variants) > 0 {
			return fmt.Errorf("padding turn length %d is not an allowed variant", totalLength)
		}
		return fmt.Errorf("padding turn length %d is outside %d-%d", totalLength, turn.minLength, turn.maxLength)
	}

	var buffer [paddingBufferLength]byte
	remaining := recordLength - headerLength
	for remaining > 0 {
		chunkLength := min(remaining, len(buffer))
		if _, err := io.ReadFull(r, buffer[:chunkLength]); err != nil {
			return fmt.Errorf("read padding body: %w", err)
		}
		remaining -= chunkLength
	}
	return nil
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
