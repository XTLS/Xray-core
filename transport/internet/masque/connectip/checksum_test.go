/* SPDX-License-Identifier: MIT
 *
 * Copyright 2024 Marten Seemann
 * Adapted from github.com/quic-go/connect-ip-go (commit a0c35fa).
 */

package connectip

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIPv4ChecksumTestVector(t *testing.T) {
	data := []byte{0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7}
	checksum := calculateIPv4Checksum(data)
	require.Equal(t, uint16(0xb861), checksum)
}

func TestIPv4ChecksumWithOptions(t *testing.T) {
	data := []byte{0x46, 0x00, 0x00, 0x77, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7, 0x94, 0x04, 0x00, 0x00}
	checksum := calculateIPv4Checksum(data)
	data[10], data[11] = byte(checksum>>8), byte(checksum)
	require.True(t, ipv4ChecksumValid(data))
	require.NotEqual(t, checksum, calculateIPv4Checksum(data[:20]), "the options must be covered")
}
