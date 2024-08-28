package segaro

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"math/big"
	mathRand "math/rand"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

// Receive buffer, then convert it into multiple chunk with padding
func segaroAddPadding(buffer *buf.Buffer, minSplitSize, maxSplitSize, paddingSize, subChunkSize int) buf.MultiBuffer {
	var chunks buf.MultiBuffer
	
	for buffer.Len() > 0 {
		chunkSize := int32(mathRand.Intn(maxSplitSize-minSplitSize+1) + minSplitSize)
		if chunkSize > buffer.Len() {
			chunkSize = buffer.Len()
		}
		// Cut the chunkSize from buffer
		chunk := buffer.BytesTo(chunkSize)
		buffer.Advance(chunkSize)

		// Split chunk into a padding chunk
		paddedChunk := addRandomPaddingAndSplit(chunk, paddingSize, subChunkSize)
		chunk = nil
		// Add the padding chunk to the chunks slice
		chunks = append(chunks, paddedChunk)
	}
	if len(chunks) == 0 {
		chunks = append(chunks, buffer)
	}
	return chunks
}

// Receive chunk and add padding to it
func addRandomPaddingAndSplit(chunk []byte, paddingSize, subChunkSize int) *buf.Buffer {
	paddedChunk := buf.New()
	getPadding := make([]byte, paddingSize)

	for len(chunk) > 0 {
		if subChunkSize > len(chunk) {
			subChunkSize = len(chunk)
		}

		// Cut subChunkSize from chunk
		subChunk := chunk[:subChunkSize]
		chunk = chunk[subChunkSize:]

		// Regenerate padding
		generatePadding(getPadding)

		// Add padding + subchunk to the chunk
		paddedChunk.Write(getPadding)
		paddedChunk.Write(subChunk)
	}

	// Free the memory
	getPadding = nil

	return paddedChunk
}

// generate padding and update paddingBuffer
func generatePadding(paddingBuffer []byte) {
	for i := range paddingBuffer {
		randomByte, err := rand.Int(rand.Reader, big.NewInt(95)) // 126 - 32 + 1 = 95
		if err != nil {
			continue
		}
		paddingBuffer[i] = byte(randomByte.Int64() + 32)
	}
}

func SegaroRemovePadding(chunks buf.MultiBuffer, paddingSize, subChunkSize int) *buf.Buffer {
	originalBuffer := buf.New()
	for _, chunk := range chunks {
		originalChunk := removePadding(chunk, paddingSize, subChunkSize)
		originalBuffer.Write(originalChunk.Bytes())

		// Free the memory
		originalChunk.Release()
		originalChunk = nil
	}
	return originalBuffer
}

func removePadding(paddedChunk *buf.Buffer, paddingSize, subChunkSize int) *buf.Buffer {
	originalChunk := buf.New()

	for {
		if int(paddedChunk.Len()) <= paddingSize {
			break // No more data left
		}

		// Skip padding
		paddedChunk.Advance(int32(paddingSize))

		if int(paddedChunk.Len()) < subChunkSize {
			subChunkSize = int(paddedChunk.Len())
		}

		subChunk := paddedChunk.BytesTo(int32(subChunkSize))
		originalChunk.Write(subChunk)

		// Remove the sub-chunk from paddedChunk
		paddedChunk.Advance(int32(subChunkSize))
	}

	return originalChunk
}

// generateRandomPacket, generate random time-based packet using sharedKey
func generateRandomPacket(buffer *buf.Buffer, sharedKey []byte, timeInterval int64, packetLength int, timeBase *time.Time) {
	timestamp := timeBase.Unix() / timeInterval
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(timestamp))

	hmac := hmac.New(sha256.New, sharedKey)
	hmac.Write(timeBytes)
	baseKey := hmac.Sum(nil)

	hkdfExpand(buffer, sha256.New, baseKey, packetLength)

	// Map the bytes to the range [32, 126] (ascii printable chars)
	for i := 0; i < int(buffer.Len()); i++ {
		buffer.SetByte(int32(i), 32+(buffer.Byte(int32(i))%(95))) // 126 - 32 + 1 = 95
	}
}

// hkdfExpand expands a key using HKDF to a desired output length
func hkdfExpand(buffer *buf.Buffer, hash func() hash.Hash, key []byte, length int) {
	h := hmac.New(hash, key)
	hashLen := h.Size()

	// Number of blocks needed
	nBlocks := (length + hashLen - 1) / hashLen

	var prevBlock []byte

	for i := 0; i < nBlocks; i++ {
		h.Reset()
		if len(prevBlock) > 0 {
			h.Write(prevBlock)
		}
		h.Write([]byte{byte(i + 1)})
		prevBlock = h.Sum(nil)
		buffer.Write(prevBlock)
	}
	prevBlock = nil
	buffer.Resize(0, int32(length))
}
