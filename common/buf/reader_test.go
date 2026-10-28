package buf_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/golang/mock/gomock"
	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/testing/mocks"
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

func TestBufferedReaderDataError(t *testing.T) {
	reader := &BufferedReader{Reader: NewReader(iotest.DataErrReader(strings.NewReader("abcd")))}
	data, err := io.ReadAll(reader)
	if string(data) != "abcd" || err != nil {
		t.Fatalf("ReadAll = %q, %v; want abcd, nil", data, err)
	}
}

func TestBufferedReaderDataErrorMixedReads(t *testing.T) {
	reader := &BufferedReader{Reader: NewReader(iotest.DataErrReader(strings.NewReader("abcd")))}
	if b, err := reader.ReadByte(); b != 'a' || err != nil {
		t.Fatalf("ReadByte = %q, %v; want a, nil", b, err)
	}
	mb, err := reader.ReadAtMost(1)
	got := mb.String()
	ReleaseMulti(mb)
	if got != "b" || err != nil {
		t.Fatalf("ReadAtMost = %q, %v; want b, nil", got, err)
	}
	mb, err = reader.ReadMultiBuffer()
	got = mb.String()
	ReleaseMulti(mb)
	if got != "cd" || (err != nil && err != io.EOF) {
		t.Fatalf("ReadMultiBuffer = %q, %v; want cd before EOF", got, err)
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatalf("ReadByte after data = %v; want EOF", err)
	}
}

func TestBufferedReaderDataErrorWriteTo(t *testing.T) {
	readError := errors.New("read failure")
	for _, tc := range []struct {
		name       string
		err        error
		readAtMost bool
	}{{"EOF", io.EOF, false}, {"read error", readError, false}, {"ReadAtMost error", readError, true}} {
		t.Run(tc.name, func(t *testing.T) {
			source := mocks.NewReader(gomock.NewController(t))
			source.EXPECT().Read(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
				return copy(p, "abcd"), tc.err
			}).Times(1)
			reader := &BufferedReader{Reader: NewReader(source)}
			var first string
			var firstErr error
			if tc.readAtMost {
				mb, err := reader.ReadAtMost(1)
				first, firstErr = mb.String(), err
				ReleaseMulti(mb)
			} else {
				var data [1]byte
				n, err := reader.Read(data[:])
				first, firstErr = string(data[:n]), err
			}
			if first != "a" || firstErr != nil {
				t.Fatalf("first read = %q, %v; want a, nil", first, firstErr)
			}
			var output bytes.Buffer
			n, err := reader.WriteTo(&output)
			wantErr := tc.err
			if wantErr == io.EOF {
				wantErr = nil
			}
			if n != 3 || output.String() != "bcd" || !errors.Is(err, wantErr) {
				t.Fatalf("WriteTo = %d, %q, %v; want 3, bcd, %v", n, output.String(), err, wantErr)
			}
			if wantErr != nil && !IsReadError(err) {
				t.Errorf("WriteTo error is not classified as a read error: %v", err)
			}
			source.EXPECT().Read(gomock.Any()).Return(0, io.EOF).Times(1)
			if _, err := reader.ReadByte(); err != io.EOF {
				t.Fatalf("ReadByte after pending error = %v; want underlying EOF", err)
			}
		})
	}
}
