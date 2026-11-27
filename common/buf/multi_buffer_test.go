package buf_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/buf"
)

func TestMultiBufferRead(t *testing.T) {
	b1 := New()
	common.Must2(b1.WriteString("ab"))

	b2 := New()
	common.Must2(b2.WriteString("cd"))
	mb := MultiBuffer{b1, b2}

	bs := make([]byte, 32)
	_, nBytes := SplitBytes(mb, bs)
	if nBytes != 4 {
		t.Error("expect 4 bytes split, but got ", nBytes)
	}
	if r := cmp.Diff(bs[:nBytes], []byte("abcd")); r != "" {
		t.Error(r)
	}
}

func TestMultiBufferAppend(t *testing.T) {
	var mb MultiBuffer
	b := New()
	common.Must2(b.WriteString("ab"))
	mb = append(mb, b)
	if mb.Len() != 2 {
		t.Error("expected length 2, but got ", mb.Len())
	}
}

func TestMultiBufferSliceBySizeLarge(t *testing.T) {
	lb := make([]byte, 8*1024)
	common.Must2(io.ReadFull(rand.Reader, lb))

	mb := MergeBytes(nil, lb)

	mb, mb2 := SplitSize(mb, 1024)
	if mb2.Len() != 1024 {
		t.Error("expect length 1024, but got ", mb2.Len())
	}
	if mb.Len() != 7*1024 {
		t.Error("expect length 7*1024, but got ", mb.Len())
	}

	mb, mb3 := SplitSize(mb, 7*1024)
	if mb3.Len() != 7*1024 {
		t.Error("expect length 7*1024, but got", mb.Len())
	}

	if !mb.IsEmpty() {
		t.Error("expect empty buffer, but got ", mb.Len())
	}
}

// newMultiBuffer returns a MultiBuffer with one Buffer per string.
func newMultiBuffer(contents ...string) MultiBuffer {
	mb := make(MultiBuffer, 0, len(contents))
	for _, s := range contents {
		b := New()
		common.Must2(b.WriteString(s))
		mb = append(mb, b)
	}
	return mb
}

func bufferStrings(mb MultiBuffer) []string {
	contents := []string(nil)
	for _, b := range mb {
		contents = append(contents, b.String())
	}
	return contents
}

func TestSplitSize(t *testing.T) {
	for _, tc := range []struct {
		name        string
		in          []string
		size        int32
		rest, chunk []string
	}{
		{"empty", nil, 4, nil, nil},
		{"whole buffers", []string{"ab", "cd", "ef"}, 5, []string{"ef"}, []string{"ab", "cd"}},
		{"exact size", []string{"ab", "cd"}, 2, []string{"cd"}, []string{"ab"}},
		{"all", []string{"ab", "cd"}, 8, nil, []string{"ab", "cd"}},
		{"first larger", []string{"abcde", "fg"}, 3, []string{"de", "fg"}, []string{"abc"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rest, chunk := SplitSize(newMultiBuffer(tc.in...), tc.size)
			if r := cmp.Diff(bufferStrings(rest), tc.rest); r != "" {
				t.Error("rest: ", r)
			}
			if r := cmp.Diff(bufferStrings(chunk), tc.chunk); r != "" {
				t.Error("chunk: ", r)
			}
		})
	}
}

// Appending to one result of SplitSize must not overwrite the other.
func TestSplitSizeAppend(t *testing.T) {
	for _, size := range []int32{4, 8} {
		// Spare capacity, so that appending to rest stays in the array of in.
		in := append(make(MultiBuffer, 0, 4), newMultiBuffer("ab", "cd", "ef")...)
		rest, chunk := SplitSize(in, size)
		restWant := append(bufferStrings(rest), "gh")
		chunkWant := append(bufferStrings(chunk), "ij")
		rest = append(rest, newMultiBuffer("gh")...)
		chunk = append(chunk, newMultiBuffer("ij")...)
		if r := cmp.Diff(bufferStrings(rest), restWant); r != "" {
			t.Error("rest: ", r)
		}
		if r := cmp.Diff(bufferStrings(chunk), chunkWant); r != "" {
			t.Error("chunk: ", r)
		}
		// XHTTP releases a chunk in its own goroutine while rest is still in use.
		ReleaseMulti(chunk)
		if r := cmp.Diff(bufferStrings(rest), restWant); r != "" {
			t.Error("rest after ReleaseMulti(chunk): ", r)
		}
	}
}

func TestSplitSizeAllocs(t *testing.T) {
	mb := newMultiBuffer("ab", "cd", "ef")
	in := make(MultiBuffer, len(mb))
	if n := testing.AllocsPerRun(100, func() {
		copy(in, mb)
		SplitSize(in, 4)
	}); n != 0 {
		t.Error("SplitSize of whole buffers: ", n, " allocs")
	}
}

func TestMultiBufferSplitFirst(t *testing.T) {
	b1 := New()
	b1.WriteString("b1")

	b2 := New()
	b2.WriteString("b2")

	b3 := New()
	b3.WriteString("b3")

	var mb MultiBuffer
	mb = append(mb, b1, b2, b3)

	mb, c1 := SplitFirst(mb)
	if diff := cmp.Diff(b1.String(), c1.String()); diff != "" {
		t.Error(diff)
	}

	mb, c2 := SplitFirst(mb)
	if diff := cmp.Diff(b2.String(), c2.String()); diff != "" {
		t.Error(diff)
	}

	mb, c3 := SplitFirst(mb)
	if diff := cmp.Diff(b3.String(), c3.String()); diff != "" {
		t.Error(diff)
	}

	if !mb.IsEmpty() {
		t.Error("expect empty buffer, but got ", mb.String())
	}
}

func TestMultiBufferReadAllToByte(t *testing.T) {
	{
		lb := make([]byte, 8*1024)
		common.Must2(io.ReadFull(rand.Reader, lb))
		rd := bytes.NewBuffer(lb)
		b, err := ReadAllToBytes(rd)
		common.Must(err)

		if l := len(b); l != 8*1024 {
			t.Error("unexpected length from ReadAllToBytes", l)
		}
	}
	{
		const dat = "data/test_MultiBufferReadAllToByte.dat"
		f, err := os.Open(dat)
		common.Must(err)

		buf2, err := ReadAllToBytes(f)
		common.Must(err)
		f.Close()

		cnt, err := os.ReadFile(dat)
		common.Must(err)

		if d := cmp.Diff(buf2, cnt); d != "" {
			t.Error("fail to read from file: ", d)
		}
	}
}

func TestMultiBufferCopy(t *testing.T) {
	lb := make([]byte, 8*1024)
	common.Must2(io.ReadFull(rand.Reader, lb))
	reader := bytes.NewBuffer(lb)

	mb, err := ReadFrom(reader)
	common.Must(err)

	lbdst := make([]byte, 8*1024)
	mb.Copy(lbdst)

	if d := cmp.Diff(lb, lbdst); d != "" {
		t.Error("unexpected different from MultiBufferCopy ", d)
	}
}

func TestSplitFirstBytes(t *testing.T) {
	a := New()
	common.Must2(a.WriteString("ab"))
	b := New()
	common.Must2(b.WriteString("bc"))

	mb := MultiBuffer{a, b}

	o := make([]byte, 2)
	_, cnt := SplitFirstBytes(mb, o)
	if cnt != 2 {
		t.Error("unexpected cnt from SplitFirstBytes ", cnt)
	}
	if d := cmp.Diff(string(o), "ab"); d != "" {
		t.Error("unexpected splited result from SplitFirstBytes ", d)
	}
}

func TestCompact(t *testing.T) {
	a := New()
	common.Must2(a.WriteString("ab"))
	b := New()
	common.Must2(b.WriteString("bc"))

	mb := MultiBuffer{a, b}
	cmb := Compact(mb)

	if w := cmb.String(); w != "abbc" {
		t.Error("unexpected Compact result ", w)
	}
}

func TestCompactWithConsumed(t *testing.T) {
	// make a consumed buffer (a.Start != 0)
	a := New()
	for range 8192 {
		common.Must2(a.WriteString("a"))
	}
	a.Read(make([]byte, 2))

	b := New()
	for range 2 {
		common.Must2(b.WriteString("b"))
	}

	mb := MultiBuffer{a, b}
	cmb := Compact(mb)
	mbc := &MultiBufferContainer{mb}
	mbc.Read(make([]byte, 8190))

	if w := cmb.String(); w != "bb" {
		t.Error("unexpected Compact result ", w)
	}
}

func BenchmarkSplitBytes(b *testing.B) {
	var mb MultiBuffer
	raw := make([]byte, Size)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buffer := StackNew()
		buffer.Extend(Size)
		mb = append(mb, &buffer)
		mb, _ = SplitBytes(mb, raw)
	}
}
