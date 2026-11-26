package serial

import (
	"encoding/binary"
	"io"
)

// ReadUint16 reads a big-endian uint16. EOF after the first byte is io.ErrUnexpectedEOF.
func ReadUint16(reader io.ByteReader) (uint16, error) {
	hi, err := reader.ReadByte()
	if err != nil {
		return 0, err
	}
	lo, err := reader.ReadByte()
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return 0, err
	}
	return uint16(hi)<<8 | uint16(lo), nil
}

// WriteUint16 writes an uint16 value into writer.
func WriteUint16(writer io.Writer, value uint16) (int, error) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], value)
	return writer.Write(b[:])
}

// WriteUint64 writes an uint64 value into writer.
func WriteUint64(writer io.Writer, value uint64) (int, error) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], value)
	return writer.Write(b[:])
}
