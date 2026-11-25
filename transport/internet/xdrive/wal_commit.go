package xdrive

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

const (
	commitSuffix   = ".commit"
	walCommitMagic = "XDWALC01"
	walCommitBytes = 8 + 8 + sha256.Size
)

func (*templateStorage) requiresWALCommit() bool {
	return true
}

func requiresWALCommit(storage Storage) bool {
	s, ok := storage.(interface{ requiresWALCommit() bool })
	return ok && s.requiresWALCommit()
}

func encodeWALCommit(data []byte) []byte {
	commit := make([]byte, walCommitBytes)
	copy(commit, walCommitMagic)
	binary.BigEndian.PutUint64(commit[8:16], uint64(len(data)))
	sum := sha256.Sum256(data)
	copy(commit[16:], sum[:])
	return commit
}

func validWALCommit(commit, data []byte) bool {
	if len(commit) != walCommitBytes || string(commit[:8]) != walCommitMagic || len(data) == 0 || len(data) > maxSegmentBytes {
		return false
	}
	if binary.BigEndian.Uint64(commit[8:16]) != uint64(len(data)) {
		return false
	}
	sum := sha256.Sum256(data)
	return bytes.Equal(commit[16:], sum[:])
}
