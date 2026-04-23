// Package encapsulation implements a way of encoding variable-size chunks of
// data and padding into a byte stream.
//
// Each chunk of data or padding starts with a variable-size length prefix. One
// bit ("d") in the first byte of the prefix indicates whether the chunk
// represents data or padding (1=data, 0=padding). Another bit ("c" for
// "continuation") is the indicates whether there are more bytes in the length
// prefix. The remaining 6 bits ("x") encode part of the length value.
// 	dcxxxxxx
// If the continuation bit is set, then the next byte is also part of the length
// prefix. It lacks the "d" bit, has its own "c" bit, and 7 value-carrying bits
// ("y").
// 	cyyyyyyy
// The length is decoded by concatenating value-carrying bits, from left to
// right, of all value-carrying bits, up to and including the first byte whose
// "c" bit is 0. Although in principle this encoding would allow for length
// prefixes of any size, length prefixes are arbitrarily limited to 3 bytes and
// any attempt to read or write a longer one is an error. These are therefore
// the only valid formats:
// 	00xxxxxx			xxxxxx₂ bytes of padding
// 	10xxxxxx			xxxxxx₂ bytes of data
// 	01xxxxxx 0yyyyyyy		xxxxxxyyyyyyy₂ bytes of padding
// 	11xxxxxx 0yyyyyyy		xxxxxxyyyyyyy₂ bytes of data
// 	01xxxxxx 1yyyyyyy 0zzzzzzz	xxxxxxyyyyyyyzzzzzzz₂ bytes of padding
// 	11xxxxxx 1yyyyyyy 0zzzzzzz	xxxxxxyyyyyyyzzzzzzz₂ bytes of data
// The maximum encodable length is 11111111111111111111₂ = 0xfffff = 1048575.
// There is no requirement to use a length prefix of minimum size; i.e. 00000100
// and 01000000 00000100 are both valid encodings of the value 4.
//
// After the length prefix follow that many bytes of padding or data. There are
// no restrictions on the value of bytes comprising padding.
//
// The idea for this encapsulation is sketched here:
// https://github.com/net4people/bbs/issues/9#issuecomment-524095186
package encapsulation

import (
	"errors"
	"io"
	"io/ioutil"
)

// ErrTooLong is the error returned when an encoded length prefix is longer than
// 3 bytes, or when ReadData receives an input whose length is too large to
// encode in a 3-byte length prefix.
var ErrTooLong = errors.New("length prefix is too long")

// ReadData returns a new slice with the contents of the next available data
// chunk, skipping over any padding chunks that may come first. The returned
// error value is nil if and only if a data chunk was present and was read in
// its entirety. The returned error is io.EOF only if r ended before the first
// byte of a length prefix. If r ended in the middle of a length prefix or
// data/padding, the returned error is io.ErrUnexpectedEOF.
func ReadData(r io.Reader) ([]byte, error) {
	for {
		var b [1]byte
		_, err := r.Read(b[:])
		if err != nil {
			// This is the only place we may return a real io.EOF.
			return nil, err
		}
		isData := (b[0] & 0x80) != 0
		moreLength := (b[0] & 0x40) != 0
		n := int(b[0] & 0x3f)
		for i := 0; moreLength; i++ {
			if i >= 2 {
				return nil, ErrTooLong
			}
			_, err := r.Read(b[:])
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			if err != nil {
				return nil, err
			}
			moreLength = (b[0] & 0x80) != 0
			n = (n << 7) | int(b[0]&0x7f)
		}
		if isData {
			p := make([]byte, n)
			_, err := io.ReadFull(r, p)
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			if err != nil {
				return nil, err
			}
			return p, err
		} else {
			_, err := io.CopyN(ioutil.Discard, r, int64(n))
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			if err != nil {
				return nil, err
			}
		}
	}
}

// dataPrefixForLength returns a length prefix for the given length, with the
// "d" bit set to 1.
func dataPrefixForLength(n int) ([]byte, error) {
	switch {
	case (n>>0)&0x3f == (n >> 0):
		return []byte{0x80 | byte((n>>0)&0x3f)}, nil
	case (n>>7)&0x3f == (n >> 7):
		return []byte{0xc0 | byte((n>>7)&0x3f), byte((n >> 0) & 0x7f)}, nil
	case (n>>14)&0x3f == (n >> 14):
		return []byte{0xc0 | byte((n>>14)&0x3f), 0x80 | byte((n>>7)&0x7f), byte((n >> 0) & 0x7f)}, nil
	default:
		return nil, ErrTooLong
	}
}

// WriteData encodes a data chunk into w. It returns the total number of bytes
// written; i.e., including the length prefix. The error is ErrTooLong if the
// length of data cannot fit into a length prefix.
func WriteData(w io.Writer, data []byte) (int, error) {
	prefix, err := dataPrefixForLength(len(data))
	if err != nil {
		return 0, err
	}
	total := 0
	n, err := w.Write(prefix)
	total += n
	if err != nil {
		return total, err
	}
	n, err = w.Write(data)
	total += n
	return total, err
}

var paddingBuffer = make([]byte, 1024)

// WritePadding encodes padding chunks, whose total size (including their own
// length prefixes) is n. Returns the total number of bytes written to w, which
// will be exactly n unless there was an error. The error cannot be ErrTooLong
// because this function will write multiple padding chunks if necessary to
// reach the requested size. Panics if n is negative.
func WritePadding(w io.Writer, n int) (int, error) {
	if n < 0 {
		panic("negative length")
	}
	total := 0
	for n > 0 {
		p := len(paddingBuffer)
		if p > n {
			p = n
		}
		n -= p
		var prefix []byte
		switch {
		case ((p-1)>>0)&0x3f == ((p - 1) >> 0):
			p = p - 1
			prefix = []byte{byte((p >> 0) & 0x3f)}
		case ((p-2)>>7)&0x3f == ((p - 2) >> 7):
			p = p - 2
			prefix = []byte{0x40 | byte((p>>7)&0x3f), byte((p >> 0) & 0x7f)}
		case ((p-3)>>14)&0x3f == ((p - 3) >> 14):
			p = p - 3
			prefix = []byte{0x40 | byte((p>>14)&0x3f), 0x80 | byte((p>>7)&0x3f), byte((p >> 0) & 0x7f)}
		}
		nn, err := w.Write(prefix)
		total += nn
		if err != nil {
			return total, err
		}
		nn, err = w.Write(paddingBuffer[:p])
		total += nn
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// MaxDataForSize returns the length of the longest slice that can be passed to
// WriteData, whose total encoded size (including length prefix) is no larger
// than n. Call this to find out if a chunk of data will fit into a length
// budget. Panics if n == 0.
func MaxDataForSize(n int) int {
	if n == 0 {
		panic("zero length")
	}
	prefix, err := dataPrefixForLength(n)
	if err == ErrTooLong {
		return (1 << (6 + 7 + 7)) - 1 - 3
	} else if err != nil {
		panic(err)
	}
	return n - len(prefix)
}
