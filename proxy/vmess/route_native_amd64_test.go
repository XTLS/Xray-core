//go:build amd64 && !purego

package vmess

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"golang.org/x/sys/cpu"
)

func requireAES(t *testing.T) {
	t.Helper()
	if !cpu.X86.HasAES || !cpu.X86.HasSSE41 {
		t.Skip("AES-NI and SSE4.1 unavailable")
	}
}

func TestPackedAES(t *testing.T) {
	requireAES(t)
	keyBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	cipherBytes, _ := hex.DecodeString("69c4e0d86a7b0430d8cdb78070b4c55a")
	plainBytes, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	var key, input, output [16]byte
	copy(key[:], keyBytes)
	copy(input[:], cipherBytes)
	var expanded schedule
	expand128(&key, &expanded)
	decrypt1(&expanded, &input, &output)
	if !bytes.Equal(output[:], plainBytes) {
		t.Fatal("AES-128 known-answer failure")
	}
	for trial := 0; trial < 1024; trial++ {
		var schedules [4]schedule
		var expected, actual [4][16]byte
		var seed [8]byte
		binary.LittleEndian.PutUint64(seed[:], uint64(trial))
		digest := sha256.Sum256(seed[:])
		copy(input[:], digest[:16])
		for lane := range schedules {
			binary.LittleEndian.PutUint64(seed[:], uint64(trial*4+lane+10000))
			digest := sha256.Sum256(seed[:])
			copy(key[:], digest[:16])
			expand128(&key, &schedules[lane])
			ref, err := aes.NewCipher(key[:])
			if err != nil {
				t.Fatal(err)
			}
			ref.Decrypt(expected[lane][:], input[:])
			decrypt1(&schedules[lane], &input, &output)
			if output != expected[lane] {
				t.Fatal("single-block differential failure", trial, lane)
			}
		}
		decrypt4(&schedules[0], &input, &actual)
		if actual != expected {
			t.Fatal("four-key differential failure", trial)
		}
		var reduced [4]reducedSchedule
		for lane := range reduced {
			reduced[lane] = reduce(&schedules[lane])
		}
		decryptReduced4(&reduced[0], &input, &actual)
		if actual != expected {
			t.Fatal("reduced schedule differential failure", trial)
		}
	}
}
