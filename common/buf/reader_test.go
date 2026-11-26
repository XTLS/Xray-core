package buf_test

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestBytesReaderWriteTo(t *testing.T) {
	pReader, pWriter := pipe.New(pipe.WithSizeLimit(1024))
	reader := &BufferedReader{Reader: pReader}
	b1 := New()
	b1.WriteString("abc")
	b2 := New()
	b2.WriteString("efg")
	common.Must(pWriter.WriteMultiBuffer(MultiBuffer{b1, b2}))
	pWriter.Close()

	pReader2, pWriter2 := pipe.New(pipe.WithSizeLimit(1024))
	writer := NewBufferedWriter(pWriter2)
	writer.SetBuffered(false)

	nBytes, err := io.Copy(writer, reader)
	common.Must(err)
	if nBytes != 6 {
		t.Error("copy: ", nBytes)
	}

	mb, err := pReader2.ReadMultiBuffer()
	common.Must(err)
	if s := mb.String(); s != "abcefg" {
		t.Error("content: ", s)
	}
}

func TestBytesReaderMultiBuffer(t *testing.T) {
	pReader, pWriter := pipe.New(pipe.WithSizeLimit(1024))
	reader := &BufferedReader{Reader: pReader}
	b1 := New()
	b1.WriteString("abc")
	b2 := New()
	b2.WriteString("efg")
	common.Must(pWriter.WriteMultiBuffer(MultiBuffer{b1, b2}))
	pWriter.Close()

	mbReader := NewReader(reader)
	mb, err := mbReader.ReadMultiBuffer()
	common.Must(err)
	if s := mb.String(); s != "abcefg" {
		t.Error("content: ", s)
	}
}

func TestReadByte(t *testing.T) {
	sr := strings.NewReader("abcd")
	reader := &BufferedReader{
		Reader: NewReader(sr),
	}
	b, err := reader.ReadByte()
	common.Must(err)
	if b != 'a' {
		t.Error("unexpected byte: ", b, " want a")
	}
	if reader.BufferedBytes() != 3 { // 3 bytes left in buffer
		t.Error("unexpected buffered Bytes: ", reader.BufferedBytes())
	}

	nBytes, err := reader.WriteTo(DiscardBytes)
	common.Must(err)
	if nBytes != 3 {
		t.Error("unexpect bytes written: ", nBytes)
	}
}

// multiBufferReader returns its MultiBuffers in order, then io.EOF.
type multiBufferReader []MultiBuffer

func (r *multiBufferReader) ReadMultiBuffer() (MultiBuffer, error) {
	if len(*r) == 0 {
		return nil, io.EOF
	}
	mb := (*r)[0]
	*r = (*r)[1:]
	return mb, nil
}

func TestReadByteAcrossBuffers(t *testing.T) {
	cached, next := New(), New()
	cached.WriteString("ab")
	next.WriteString("c")
	// After the cached buffer, an empty read comes before the next buffer.
	reader := &BufferedReader{Buffer: MultiBuffer{cached}, Reader: &multiBufferReader{nil, MultiBuffer{next}}}
	readByte := func(want byte) {
		t.Helper()
		if c, err := reader.ReadByte(); c != want || err != nil {
			t.Fatalf("ReadByte() = %q, %v, want %q, nil", c, err, want)
		}
	}
	readByte('a')
	readByte('b')
	if reader.Buffer != nil {
		t.Fatal("ReadByte kept the emptied buffer: ", reader.Buffer)
	}
	readByte('c')
	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatalf("ReadByte() error = %v, want EOF", err)
	}
}

func TestReadByteAllocs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		splitter func(MultiBuffer, []byte) (MultiBuffer, int)
	}{
		{"cached buffer", nil},
		// An explicit Splitter takes the path through Read.
		{"Read", SplitBytes},
	} {
		b := New()
		b.Extend(Size)
		reader := &BufferedReader{Buffer: MultiBuffer{b}, Splitter: tc.splitter}
		if n := testing.AllocsPerRun(100, func() { reader.ReadByte() }); n != 0 {
			t.Errorf("ReadByte through %s: %v allocs", tc.name, n)
		}
	}
}

func TestReadBuffer(t *testing.T) {
	{
		sr := strings.NewReader("abcd")
		buf, err := ReadBuffer(sr)
		common.Must(err)

		if s := buf.String(); s != "abcd" {
			t.Error("unexpected str: ", s, " want abcd")
		}
		buf.Release()
	}
}

func TestReadAtMost(t *testing.T) {
	sr := strings.NewReader("abcd")
	reader := &BufferedReader{
		Reader: NewReader(sr),
	}

	mb, err := reader.ReadAtMost(3)
	common.Must(err)
	if s := mb.String(); s != "abc" {
		t.Error("unexpected read result: ", s)
	}

	nBytes, err := reader.WriteTo(DiscardBytes)
	common.Must(err)
	if nBytes != 1 {
		t.Error("unexpect bytes written: ", nBytes)
	}
}

func TestPacketReader_ReadMultiBuffer(t *testing.T) {
	const alpha = "abcefg"
	buf := bytes.NewBufferString(alpha)
	reader := &PacketReader{buf}
	mb, err := reader.ReadMultiBuffer()
	common.Must(err)
	if s := mb.String(); s != alpha {
		t.Error("content: ", s)
	}
}

func TestReaderInterface(t *testing.T) {
	_ = io.Reader(new(ReadVReader))
	_ = Reader(new(ReadVReader))

	_ = Reader(new(BufferedReader))
	_ = io.Reader(new(BufferedReader))
	_ = io.ByteReader(new(BufferedReader))
	_ = io.WriterTo(new(BufferedReader))
}
