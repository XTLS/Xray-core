package buf

import (
	"io"

	"github.com/xtls/xray-core/common/bytespool"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

const (
	// Size of a regular buffer.
	Size = 8192
)

var ErrBufferFull = errors.New("buffer is full")
var pool = bytespool.GetPool(Size)

// ownership represents the data owner of the buffer.
type ownership uint8

const (
	managed ownership = iota
	unmanaged
	bytespools
)

// Buffer is a recyclable allocation of a byte array. Buffer.Release() recycles
// the buffer into an internal buffer pool, in order to recreate a buffer more
// quickly.
type Buffer struct {
	v         []byte
	start     int32
	end       int32
	ownership ownership
	UDP       *net.Destination
}

// New creates a Buffer with 0 length and 8K capacity, managed.
func New() *Buffer {
	v := pool.Get()
	b, ok := v.([]byte)
	if !ok || cap(b) < Size {
		b = make([]byte, Size)
	}
	b = b[:Size:Size]
	return &Buffer{v: b}
}

// NewExisted creates a standard size Buffer with an existed bytearray, managed
// Panics if cap(b) < Size or len(b) overflows int32.
func NewExisted(b []byte) *Buffer {
	if cap(b) < Size {
		panic("Invalid buffer")
	}

	oLen := len(b)
	oLen32 := int32(oLen)
	if int(oLen32) != oLen {
		panic("Invalid buffer length")
	}

	if oLen < Size {
		b = b[:Size:Size]
	}

	return &Buffer{
		v:   b,
		end: oLen32,
	}
}

// FromBytes creates a Buffer with an existed bytearray, unmanaged.
// Panics if len(b) exceeds int32; capacity is fixed via b[:n:n].
func FromBytes(b []byte) *Buffer {
	const maxInt32 = 1<<31 - 1
	n := len(b)
	if n > maxInt32 {
		panic("buffer too large")
	}
	v := b[:n:n]
	return &Buffer{
		v:         v,
		end:       int32(n),
		ownership: unmanaged,
	}
}

// StackNew creates a new Buffer object on stack, managed.
// This method is for buffers that are released in the same function.
func StackNew() Buffer {
	v := pool.Get()
	b, ok := v.([]byte)
	if !ok || cap(b) < Size {
		b = make([]byte, Size)
	}
	b = b[:Size:Size]
	return Buffer{v: b}
}

// NewWithSize creates a Buffer with 0 length and capacity at least size, bytespool-backed.
func NewWithSize(size int32) *Buffer {
	return &Buffer{
		v:         bytespool.Alloc(size),
		ownership: bytespools,
	}
}

// Release recycles the buffer into an internal buffer pool.
// Zeroes the used range; no-op for nil or unmanaged.
func (b *Buffer) Release() {
	if b == nil {
		return
	}
	p := b.v
	o := b.ownership
	usedStart, usedEnd := b.start, b.end

	b.v = nil
	b.start, b.end = 0, 0
	b.UDP = nil

	if p == nil || o == unmanaged {
		return
	}

	if usedEnd > usedStart && int(usedEnd) <= len(p) {
		clear(p[usedStart:usedEnd])
	}

	switch o {
	case managed:
		if cap(p) == Size {
			pool.Put(p)
		}
	case bytespools:
		bytespool.Free(p)
	}
}

// Clear clears the content of the buffer, results an empty buffer with Len() = 0.
// No-op for nil.
func (b *Buffer) Clear() {
	if b == nil {
		return
	}
	b.start, b.end = 0, 0
}

// Byte returns the bytes at index.
func (b *Buffer) Byte(index int32) byte {
	return b.v[b.start+index]
}

// SetByte sets the byte value at index.
func (b *Buffer) SetByte(index int32, value byte) {
	b.v[b.start+index] = value
}

// Bytes returns the content bytes of this Buffer.
func (b *Buffer) Bytes() []byte {
	return b.v[b.start:b.end]
}

// Extend increases the buffer size by n bytes, and returns the extended part.
// Panics on negative n or if capacity is exceeded.
func (b *Buffer) Extend(n int32) []byte {
	if n == 0 {
		return b.v[b.end:b.end]
	}
	if n < 0 {
		panic("extending out of bounds")
	}
	avail := int32(len(b.v)) - b.end
	if n > avail {
		panic("extending out of bounds")
	}
	oldEnd := b.end
	b.end += n
	return b.v[oldEnd:b.end]
}

// BytesRange returns a slice of this buffer with given from and to boundary.
// Negative indices are clamped and from ≤ to is enforced.
func (b *Buffer) BytesRange(from, to int32) []byte {
	l := b.Len()

	if from < 0 {
		from += l
	}
	if to < 0 {
		to += l
	}
	from = min(max(from, 0), l)
	to = min(max(to, 0), l)

	if to < from {
		to = from
	}

	start := b.start + from
	end := b.start + to
	return b.v[start:end]
}

// BytesFrom returns a slice of this Buffer starting from the given position.
// Negative index is clamped.
func (b *Buffer) BytesFrom(from int32) []byte {
	return b.BytesRange(from, b.Len())
}

// BytesTo returns a slice of this Buffer from start to the given position.
// Negative index is clamped.
func (b *Buffer) BytesTo(to int32) []byte {
	return b.BytesRange(0, to)
}

// Check makes sure that 0 <= b.start <= b.end <= int32(len(b.v)).
// No-op for nil.
func (b *Buffer) Check() {
	if b == nil {
		return
	}
	cap32 := int32(len(b.v))
	e := min(max(b.end, 0), cap32)
	s := min(max(b.start, 0), e)
	if s != b.start || e != b.end {
		b.start, b.end = s, e
	}
}

// Resize cuts the buffer to [from:to] relative to current content (negative indices allowed).
// Panics if to < from or capacity is exceeded.
// Zeroes any newly exposed region.
func (b *Buffer) Resize(from, to int32) {
	oldEnd := b.end
	l := b.Len()
	if from < 0 {
		from += l
	}
	if to < 0 {
		to += l
	}
	if to < from {
		panic("Invalid slice")
	}
	newStart := b.start + from
	newEnd := b.start + to
	if newEnd > int32(len(b.v)) {
		panic("extending out of bound")
	}
	b.start = newStart
	b.end = newEnd
	b.Check()
	if b.end > oldEnd {
		clear(b.v[oldEnd:b.end])
	}
}

// Advance cuts the buffer by moving start by from relative to current length.
// Negative allowed and clamped.
func (b *Buffer) Advance(from int32) {
	l := b.end - b.start
	if from < 0 {
		from += l
	}
	from = min(max(from, 0), l)
	b.start += from
	b.Check()
}

// Len returns the length of the buffer content.
func (b *Buffer) Len() int32 {
	if b == nil {
		return 0
	}
	return b.end - b.start
}

// Cap returns the capacity of the buffer content.
func (b *Buffer) Cap() int32 {
	if b == nil {
		return 0
	}
	return int32(len(b.v))
}

// Available returns the available capacity of the buffer content.
func (b *Buffer) Available() int32 {
	if b == nil {
		return 0
	}
	return int32(len(b.v)) - b.end
}

// IsEmpty returns true if the buffer is empty.
func (b *Buffer) IsEmpty() bool {
	return b.Len() == 0
}

// IsFull returns true if the buffer has no more room to grow.
func (b *Buffer) IsFull() bool {
	return b != nil && b.end == int32(len(b.v))
}

// Write implements Write method in io.Writer.
// Returns ErrBufferFull on short write.
// Returns 0, nil on empty input.
func (b *Buffer) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	end := b.end
	n := copy(b.v[end:], data)
	b.end = end + int32(n)
	if n != len(data) {
		return n, ErrBufferFull
	}
	return n, nil
}

// WriteByte writes a single byte into the buffer.
func (b *Buffer) WriteByte(v byte) error {
	if b.end == int32(len(b.v)) {
		return ErrBufferFull
	}
	i := b.end
	b.v[i] = v
	b.end = i + 1
	return nil
}

// WriteString implements io.StringWriter.
// Returns ErrBufferFull on short write.
// Returns 0, nil on empty input.
func (b *Buffer) WriteString(s string) (int, error) {
	if len(s) == 0 {
		return 0, nil
	}
	end := b.end
	n := copy(b.v[end:], s)
	b.end = end + int32(n)
	if n != len(s) {
		return n, ErrBufferFull
	}
	return n, nil
}

// ReadByte implements io.ByteReader
func (b *Buffer) ReadByte() (byte, error) {
	if b.start == b.end {
		return 0, io.EOF
	}
	i := b.start
	v := b.v[i]
	b.start = i + 1
	return v, nil
}

// ReadBytes implements bufio.Reader.ReadBytes.
// Panics if length < 0.
// Returns io.EOF if insufficient data.
func (b *Buffer) ReadBytes(length int32) ([]byte, error) {
	if length < 0 {
		panic("invalid length")
	}
	avail := b.end - b.start
	if avail < length {
		return nil, io.EOF
	}
	start := b.start
	end := start + length
	b.start = end
	return b.v[start:end], nil
}

// Read implements io.Reader.Read().
func (b *Buffer) Read(data []byte) (int, error) {
	if b.Len() == 0 {
		if len(data) == 0 {
			return 0, nil
		}
		return 0, io.EOF
	}
	nBytes := copy(data, b.v[b.start:b.end])
	b.start += int32(nBytes)
	if b.start == b.end {
		b.Clear()
	}
	return nBytes, nil
}

// ReadFrom implements io.ReaderFrom.
// Reads into remaining capacity and suppresses io.EOF when n > 0.
// Returns (0, nil) if no capacity remains.
func (b *Buffer) ReadFrom(reader io.Reader) (int64, error) {
	dst := b.v[b.end:]
	if len(dst) == 0 {
		return 0, nil
	}

	n, err := reader.Read(dst)
	if n > 0 {
		b.end += int32(n)
		if err == io.EOF {
			return int64(n), nil
		}
		return int64(n), err
	}

	return 0, err
}

// ReadFullFrom reads exact size of bytes from given reader, or until error occurs.
// Panics if size < 0.
// Returns an error if size exceeds Available().
func (b *Buffer) ReadFullFrom(reader io.Reader, size int32) (int64, error) {
	if size == 0 {
		return 0, nil
	}
	if size < 0 {
		panic("invalid size")
	}
	if size > b.Available() {
		v := int64(b.end) + int64(size)
		return 0, errors.New("out of bound: ", v)
	}

	start := b.end
	end := start + size
	n, err := io.ReadFull(reader, b.v[start:end])
	b.end = start + int32(n)
	return int64(n), err
}

// String returns the string form of this Buffer.
func (b *Buffer) String() string {
	return string(b.Bytes())
}
