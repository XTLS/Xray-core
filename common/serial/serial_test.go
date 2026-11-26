package serial_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/serial"
)

func TestUint16Serial(t *testing.T) {
	b := buf.New()
	defer b.Release()

	n, err := serial.WriteUint16(b, 10)
	common.Must(err)
	if n != 2 {
		t.Error("expect 2 bytes writtng, but actually ", n)
	}
	if diff := cmp.Diff(b.Bytes(), []byte{0, 10}); diff != "" {
		t.Error(diff)
	}
}

func TestUint64Serial(t *testing.T) {
	b := buf.New()
	defer b.Release()

	n, err := serial.WriteUint64(b, 10)
	common.Must(err)
	if n != 8 {
		t.Error("expect 8 bytes writtng, but actually ", n)
	}
	if diff := cmp.Diff(b.Bytes(), []byte{0, 0, 0, 0, 0, 0, 0, 10}); diff != "" {
		t.Error(diff)
	}
}

func TestReadUint16(t *testing.T) {
	testCases := []struct {
		Input  []byte
		Output uint16
		Error  error
	}{
		{Input: []byte{1, 2}, Output: 0x0102},
		{Error: io.EOF},
		{Input: []byte{1}, Error: io.ErrUnexpectedEOF},
	}

	for _, testCase := range testCases {
		v, err := serial.ReadUint16(bytes.NewReader(testCase.Input))
		if v != testCase.Output || err != testCase.Error {
			t.Errorf("ReadUint16(%v) = %v, %v, want %v, %v", testCase.Input, v, err, testCase.Output, testCase.Error)
		}
	}
}

func TestReadUint16Allocs(t *testing.T) {
	b := buf.New()
	defer b.Release()
	if n := testing.AllocsPerRun(100, func() { b.Clear(); b.Extend(2); serial.ReadUint16(b) }); n != 0 {
		t.Errorf("ReadUint16 from buf.Buffer: %v allocs", n)
	}
}

func BenchmarkReadUint16(b *testing.B) {
	reader := buf.New()
	defer reader.Release()

	common.Must2(reader.Write([]byte{0, 1}))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := serial.ReadUint16(reader)
		common.Must(err)
		reader.Clear()
		reader.Extend(2)
	}
}

func BenchmarkWriteUint64(b *testing.B) {
	writer := buf.New()
	defer writer.Release()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := serial.WriteUint64(writer, 8)
		common.Must(err)
		writer.Clear()
	}
}
